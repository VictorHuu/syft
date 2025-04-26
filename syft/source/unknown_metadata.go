package source

// UnknownMetadata represents the CycloneComponentType that Syft can't handle at present
type UnknownMetadata struct {
	UserInput      string `json:"userInput"`
	ID             string `json:"bom-ref"`
	Name           string `json:"name"`
	ManifestDigest string `json:"version"`
}
