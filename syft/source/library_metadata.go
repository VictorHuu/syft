package source

// LibraryMetadata represents the ComponentTypeLibrary defined in CycloneDX
type LibraryMetadata struct {
	UserInput   string `json:"name" yaml:"name"`
	ID          string `json:"bom-ref" yaml:"bom-ref"`
	Version     string `json:"version" yaml:"version"`
	Group       string `json:"group" yaml:"group"`
	Description string `json:"description" yaml:"description"`
	PackageURL  string `json:"purl" yaml:"purl"`
}
