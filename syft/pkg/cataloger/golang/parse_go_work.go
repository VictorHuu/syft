package golang

import (
	"bufio"
	"context"
	"fmt"
	"github.com/anchore/syft/internal/cache"
	"io"
	"io/fs"
	"sort"
	"strings"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/licenses"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

type goWorkCataloger struct {
	licenseResolver goLicenseResolver
	goWorkCache     cache.Resolver[*modfile.WorkFile]
}

func newGoWorkCataloger(opts CatalogerConfig) *goWorkCataloger {
	return &goWorkCataloger{
		licenseResolver: newGoLicenseResolver(workFileCatalogerName, opts),
	}
}

var workfiles map[string]*modfile.WorkFile

func (c *goWorkCataloger) buildGoPkg(ctx context.Context, resolver file.Resolver, reader file.LocationReadCloser,
	m module.Version, licenseScanner licenses.Scanner, digests map[string]string) pkg.Package {
	lics := c.licenseResolver.getLicenses(ctx, licenseScanner, resolver, m.Path, m.Version)
	p := pkg.Package{
		Name:      m.Path,
		Version:   m.Version,
		Licenses:  pkg.NewLicenseSet(lics...),
		Locations: file.NewLocationSet(reader.Location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation)),
		PURL:      packageURL(m.Path, m.Version),
		Language:  pkg.Go,
		Type:      pkg.GoModulePkg,
		Metadata: pkg.GolangModuleEntry{
			H1Digest: digests[fmt.Sprintf("%s %s", m.Path, m.Version)],
		},
	}
	p.SetID()
	return p
}
func (c *goWorkCataloger) getGoModFile(resolver file.Resolver, path string) (mod *modfile.File, err error) {
	locations, err := resolver.FilesByPath(strings.TrimPrefix(path, "."))
	if err != nil {
		return nil, err
	}

	for _, l := range locations {
		//TODO:fileName to reader
		readcloser, err := resolver.FileContentsByLocation(l)
		if err != nil {
			return nil, err
		}
		defer internal.CloseAndLogError(readcloser, l.RealPath)
		reader := file.NewLocationReadCloser(l, readcloser)
		contents, err := io.ReadAll(reader)
		if err != nil {
			return nil, fmt.Errorf("failed to read go module: %w", err)
		}

		f, err := modfile.Parse(l.RealPath, contents, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to parse go module: %w", err)
		}
		mod = f
		break
	}
	return
}
func (c *goWorkCataloger) recursivelyBuildGoModuleRels(ctx context.Context, resolver file.Resolver, reader file.LocationReadCloser,
	wf *modfile.WorkFile, licenseScanner licenses.Scanner, digests map[string]string) (packages map[string]pkg.Package, rels []artifact.Relationship, err error) {
	if wf == nil {
		return
	}
	if len(workfiles) == 0 {
		workfiles = make(map[string]*modfile.WorkFile)
	}
	if len(packages) == 0 {
		packages = make(map[string]pkg.Package)
	}
	mainmodulePath := fmt.Sprintf("%sgo.mod", strings.TrimSuffix(reader.Path(), "go.work"))
	mainModFile, err := c.getGoModFile(resolver, mainmodulePath)
	mainMod := mainModFile.Module.Mod
	mainModulePackage := c.buildGoPkg(ctx, resolver, reader, mainMod, licenseScanner, digests)

	var subdeps []pkg.Package
	for _, u := range wf.Use {
		if strings.EqualFold(u.Path, ".") {
			continue
		}
		subModFile, serr := c.getGoModFile(resolver,
			fmt.Sprintf("%s/go.mod", u.Path))
		if serr != nil {
			continue
		}
		subMod := subModFile.Module.Mod
		subWorkFile, serr := c.getGoWorkFile(resolver,
			fmt.Sprintf("%s/go.work", u.Path))
		if serr != nil {
			continue
		}
		/*if strings.Contains(subMod.Path, ".") && (!strings.Contains(subMod.Path, "github.com") && !strings.Contains(subMod.Path, "golang.org")) {
			err = fmt.Errorf("not a valid go.mod")
			return
		}*/
		subModulePackage := c.buildGoPkg(ctx, resolver, reader, subMod, licenseScanner, digests)
		if len(subMod.Path) == 0 {
			continue
		}
		packages[subMod.Path] = subModulePackage
		//subdeps are the immediate submodule to the main package
		subdeps = append(subdeps, subModulePackage)
		if subWorkFile == nil {
			continue
		}
		_, sub_rels, err := c.recursivelyBuildGoModuleRels(ctx, resolver, reader, subWorkFile, licenseScanner, digests)
		if err != nil {
			continue
		}
		rels = append(rels, sub_rels...)
	}
	workfiles[reader.RealPath] = wf

	m_rels := c.createModuleRelationships(mainModulePackage, subdeps)
	rels = append(rels, m_rels...)
	return
}

func (c *goWorkCataloger) createModuleRelationships(main pkg.Package, deps []pkg.Package) []artifact.Relationship {
	var relationships []artifact.Relationship

	for _, dep := range deps {
		relationships = append(relationships, artifact.Relationship{
			From: dep,
			To:   main,
			Type: artifact.ContainsRelationship,
		})
	}

	return relationships
}

// parseGoWorkFile takes a go.work and lists all submodules discovered.
//
//nolint:funlen
func (c *goWorkCataloger) parseGoWorkFile(ctx context.Context, resolver file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	licenseScanner, err := licenses.ContextLicenseScanner(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to create default license scanner: %w", err)
	}
	contents, err := io.ReadAll(reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read go work: %w", err)
	}

	wf, err := modfile.ParseWork(reader.RealPath, contents, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse go work: %w", err)
	}

	digests, err := parseGoWorkSumFile(resolver, reader)
	if err != nil {
		log.Debugf("unable to get go.work.sum: %v", err)
	}

	pkgs, rels, _ := c.recursivelyBuildGoModuleRels(ctx, resolver, reader, wf, licenseScanner, digests)

	pkgsSlice := make([]pkg.Package, len(pkgs))
	idx := 0
	for _, p := range pkgs {
		pkgsSlice[idx] = p
		idx++
	}

	sort.SliceStable(pkgsSlice, func(i, j int) bool {
		return pkgsSlice[i].Name < pkgsSlice[j].Name
	})
	return pkgsSlice, rels, nil
}

// TODO
func (c *goWorkCataloger) getGoWorkfileFromRemote(moduleName, moduleVersion string) (*modfile.WorkFile, error) {
	//return c.goModCache.Resolve(fmt.Sprintf("%s/%s", moduleName, moduleVersion), func() (*modfile.WorkFile, error) {
	proxies := remotesForModule(c.licenseResolver.opts.Proxies, c.licenseResolver.opts.NoProxy, moduleName)

	urlPrefix, fsys, err := getModule(proxies, moduleName, moduleVersion)
	if err != nil {
		return nil, err
	}

	return c.findGoWorkfileInFS(urlPrefix, fsys)
	//})
}

// TODO
func (c *goWorkCataloger) findGoWorkfileInFS(urlPrefix string, fsys fs.FS) (*modfile.WorkFile, error) {
	var out *modfile.WorkFile
	err := fs.WalkDir(fsys, ".", func(filePath string, d fs.DirEntry, err error) error {
		if err != nil {
			log.Debugf("error reading %s#%s: %v", urlPrefix, filePath, err)
			return err
		}
		if d == nil {
			log.Debugf("nil entry for %s#%s", urlPrefix, filePath)
			return nil
		}
		if !strings.EqualFold(strings.ToLower(d.Name()), "go.work") {
			return nil
		}
		rdr, err := fsys.Open(filePath)
		if err != nil {
			log.Debugf("error opening go.work :%v", err)
			return nil
		}
		defer internal.CloseAndLogError(rdr, filePath)
		readcloser := file.NewLocationReadCloser(file.NewLocation(filePath), rdr)
		defer internal.CloseAndLogError(readcloser, filePath)
		contents, err := io.ReadAll(readcloser)
		if err != nil {
			return nil
		}

		f, err := modfile.ParseWork(filePath, contents, nil)
		if err != nil {
			return nil
		}
		out = f
		return nil
	})
	return out, err
}

// TODO: Get immediate go.mod recursively to build relationships
func (c *goWorkCataloger) getGoWorkFile(resolver file.Resolver, modulePath string) (mod *modfile.WorkFile, err error) {
	mod, err = findGoWorkFile(resolver,
		fmt.Sprintf(`**%s`, strings.TrimPrefix(modulePath, ".")))
	return mod, err
}

// TODO
func findGoWorkFile(resolver file.Resolver, globMatch string) (out *modfile.WorkFile, err error) {
	if resolver == nil {
		return
	}

	locations, err := resolver.FilesByGlob(globMatch)
	if err != nil {
		return nil, err
	}

	for _, l := range locations {
		//TODO:fileName to reader
		readcloser, err := resolver.FileContentsByLocation(l)
		if err != nil {
			return nil, err
		}
		defer internal.CloseAndLogError(readcloser, l.RealPath)
		reader := file.NewLocationReadCloser(l, readcloser)
		contents, err := io.ReadAll(reader)
		if err != nil {
			return nil, fmt.Errorf("failed to read go module: %w", err)
		}

		f, err := modfile.ParseWork(l.RealPath, contents, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to parse go module: %w", err)
		}
		out = f
		break
	}
	return
}
func parseGoWorkSumFile(resolver file.Resolver, reader file.LocationReadCloser) (map[string]string, error) {
	out := map[string]string{}

	if resolver == nil {
		return out, fmt.Errorf("no resolver provided")
	}

	goWorkSumPath := fmt.Sprintf("%s.sum", reader.Location.RealPath)
	goWorkSumLocation := resolver.RelativeFileByPath(reader.Location, goWorkSumPath)
	if goWorkSumLocation == nil {
		return nil, fmt.Errorf("unable to resolve: %s", goWorkSumPath)
	}
	contents, err := resolver.FileContentsByLocation(*goWorkSumLocation)
	if err != nil {
		return nil, err
	}
	defer internal.CloseAndLogError(contents, goWorkSumLocation.AccessPath)

	// go.work.sum has the format like:
	// github.com/BurntSushi/toml v0.3.1/go.mod h1:xHWCNGjB5oqiDr8zfno3MHue2Ht5sIBksp03qcyfWMU=
	// github.com/BurntSushi/toml v0.4.1 h1:GaI7EiDXDRfa8VshkTj7Fym7ha+y8/XxIgD2okUIjLw=
	// github.com/BurntSushi/toml v0.4.1/go.mod h1:CxXYINrC8qIiEnFrOxCa7Jy5BFHlXnUU2pbicEuybxQ=
	scanner := bufio.NewScanner(contents)
	// optionally, resize scanner's capacity for lines over 64K, see next example
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, " ")
		if len(parts) < 3 {
			continue
		}
		nameVersion := fmt.Sprintf("%s %s", parts[0], parts[1])
		hash := parts[2]
		out[nameVersion] = hash
	}

	return out, nil
}
