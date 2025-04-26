package source

// ApplicationMetadata represents the ComponentTypeApplication defined in CycloneDX
type ApplicationMetadata struct {
	UserInput   string `json:"name" yaml:"name"`
	ID          string `json:"bom-ref" yaml:"bom-ref"`
	Version     string `json:"version" yaml:"version"`
	Group       string `json:"group" yaml:"group"`
	Description string `json:"description" yaml:"description"`
	PackageURL  string `json:"purl" yaml:"purl"`
}

type ExternalReferencesMetadata struct {
	Type string `json:"type" yaml:"type"`
	URL  string `json:"url" yaml:"url"`
}
