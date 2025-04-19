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

type goModCataloger struct {
	licenseResolver goLicenseResolver
	goModCache      cache.Resolver[*modfile.File]
}

func newGoModCataloger(opts CatalogerConfig) *goModCataloger {
	return &goModCataloger{
		licenseResolver: newGoLicenseResolver(modFileCatalogerName, opts),
	}
}

var modfiles map[string]*modfile.File

func (c *goModCataloger) buildGoPkg(ctx context.Context, resolver file.Resolver, reader file.LocationReadCloser,
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
func (c *goModCataloger) recursivelyBuildGoDeps(ctx context.Context, resolver file.Resolver, reader file.LocationReadCloser,
	f *modfile.File, licenseScanner licenses.Scanner, digests map[string]string) (packages map[string]pkg.Package, rels []artifact.Relationship, err error) {
	if f == nil {
		return
	}
	if len(modfiles) == 0 {
		modfiles = make(map[string]*modfile.File)
	}
	if _, exists := modfiles[f.Module.Mod.Path]; exists {
		return
	}
	modfiles[f.Module.Mod.Path] = f
	if len(packages) == 0 {
		packages = make(map[string]pkg.Package)
	}
	if _, exists := packages[f.Module.Mod.Path]; !exists {
		packages[f.Module.Mod.Path] = c.buildGoPkg(ctx, resolver, reader, f.Module.Mod, licenseScanner, digests)
	}
	var deps []pkg.Package
	for _, m := range f.Require {
		if m.Indirect {
			continue
		}
		_, exists := packages[m.Mod.Path]
		if exists {
			continue
		}
		packages[m.Mod.Path] = c.buildGoPkg(ctx, resolver, reader, m.Mod, licenseScanner, digests)
		//deps are the immediate ones to the main package
		deps = append(deps, packages[m.Mod.Path])
		nf, err := c.getGoModFile(resolver, m.Mod.Path, m.Mod.Version)
		if err != nil {
			continue
		}
		sub_pkgs, sub_rels, err := c.recursivelyBuildGoDeps(ctx, resolver, reader, nf, licenseScanner, digests)
		if err != nil {
			continue
		}
		for k, v := range sub_pkgs {
			if _, exists := packages[k]; !exists {
				packages[k] = v
			}
		}
		rels = append(rels, sub_rels...)
	}
	m_rels := createModuleRelationships(packages[f.Module.Mod.Path], deps)
	rels = append(rels, m_rels...)
	// remove any old packages and replace with new ones...
	for _, m := range f.Replace {
		// the old path and new path may be the same, in which case this is a noop,
		// but if they're different we need to remove the old package.
		delete(packages, m.Old.Path)

		packages[m.New.Path] = c.buildGoPkg(ctx, resolver, reader, m.New, licenseScanner, digests)
	}

	// remove any packages from the exclude fields
	for _, m := range f.Exclude {
		delete(packages, m.Mod.Path)
	}
	return
}

// parseGoModFile takes a go.mod and lists all packages discovered.
//
//nolint:funlen
func (c *goModCataloger) parseGoModFile(ctx context.Context, resolver file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	licenseScanner, err := licenses.ContextLicenseScanner(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to create default license scanner: %w", err)
	}

	contents, err := io.ReadAll(reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read go module: %w", err)
	}

	if strings.Contains(reader.RealPath, "test") || strings.Contains(reader.RealPath, "mock") || strings.Contains(reader.RealPath, "generator") || strings.Contains(reader.RealPath, "hack") {
		return nil, nil, fmt.Errorf("This is a go.mod for test")
	}
	fmt.Println(reader.RealPath)
	f, err := modfile.Parse(reader.RealPath, contents, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse go module: %w", err)
	}

	digests, err := parseGoSumFile(resolver, reader)
	if err != nil {
		log.Debugf("unable to get go.sum: %v", err)
	}

	packages, rels, _ := c.recursivelyBuildGoDeps(ctx, resolver, reader, f, licenseScanner, digests)

	pkgsSlice := make([]pkg.Package, len(packages))
	idx := 0
	for _, p := range packages {
		pkgsSlice[idx] = p
		idx++
	}

	sort.SliceStable(pkgsSlice, func(i, j int) bool {
		return pkgsSlice[i].Name < pkgsSlice[j].Name
	})
	fmt.Println("--------")
	return pkgsSlice, rels, nil
}

// TODO
func (c *goModCataloger) getGoModfileFromRemote(moduleName, moduleVersion string) (*modfile.File, error) {
	//return c.goModCache.Resolve(fmt.Sprintf("%s/%s", moduleName, moduleVersion), func() (*modfile.File, error) {
	proxies := remotesForModule(c.licenseResolver.opts.Proxies, c.licenseResolver.opts.NoProxy, moduleName)

	urlPrefix, fsys, err := getModule(proxies, moduleName, moduleVersion)
	if err != nil {
		return nil, err
	}

	return c.findGoModfileInFS(urlPrefix, fsys)
	//})
}

// TODO
func (c *goModCataloger) findGoModfileInFS(urlPrefix string, fsys fs.FS) (*modfile.File, error) {
	var out *modfile.File
	err := fs.WalkDir(fsys, ".", func(filePath string, d fs.DirEntry, err error) error {
		if err != nil {
			log.Debugf("error reading %s#%s: %v", urlPrefix, filePath, err)
			return err
		}
		if d == nil {
			log.Debugf("nil entry for %s#%s", urlPrefix, filePath)
			return nil
		}
		if !strings.EqualFold(strings.ToLower(d.Name()), "go.mod") {
			return nil
		}
		rdr, err := fsys.Open(filePath)
		if err != nil {
			log.Debugf("error opening go.mod :%v", err)
			return nil
		}
		defer internal.CloseAndLogError(rdr, filePath)
		readcloser := file.NewLocationReadCloser(file.NewLocation(filePath), rdr)
		defer internal.CloseAndLogError(readcloser, filePath)
		contents, err := io.ReadAll(readcloser)
		if err != nil {
			return nil
		}

		f, err := modfile.Parse(filePath, contents, nil)
		if err != nil {
			return nil
		}
		out = f
		return nil
	})
	return out, err
}

// TODO: Get immediate go.mod recursively to build relationships
func (c *goModCataloger) getGoModFile(resolver file.Resolver, moduleName, moduleVersion string) (mod *modfile.File, err error) {
	mod, err = findGoModFile(resolver,
		fmt.Sprintf(`**/go/pkg/mod/%s@%s/*`, processCaps(moduleName), moduleVersion),
	)
	if err != nil {
		return mod, err
	}
	//// look in the local host mod cache...
	//mods, err = c.getGoModfilesFromLocal(moduleName, moduleVersion)
	//if err != nil || len(mods) > 0 {
	//	return requireCollection(mods), err
	//}
	//
	// we did not find it yet and remote searching was enabled
	mod, err = c.getGoModfileFromRemote(moduleName, moduleVersion)
	return mod, err
}

// TODO
func findGoModFile(resolver file.Resolver, globMatch string) (out *modfile.File, err error) {
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

		f, err := modfile.Parse(l.RealPath, contents, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to parse go module: %w", err)
		}
		out = f
		break
	}
	return
}
func parseGoSumFile(resolver file.Resolver, reader file.LocationReadCloser) (map[string]string, error) {
	out := map[string]string{}

	if resolver == nil {
		return out, fmt.Errorf("no resolver provided")
	}

	goSumPath := strings.TrimSuffix(reader.Location.RealPath, ".mod") + ".sum"
	goSumLocation := resolver.RelativeFileByPath(reader.Location, goSumPath)
	if goSumLocation == nil {
		return nil, fmt.Errorf("unable to resolve: %s", goSumPath)
	}
	contents, err := resolver.FileContentsByLocation(*goSumLocation)
	if err != nil {
		return nil, err
	}
	defer internal.CloseAndLogError(contents, goSumLocation.AccessPath)

	// go.sum has the format like:
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
