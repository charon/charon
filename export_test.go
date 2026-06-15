package charon

// GravatarURL exposes the unexported gravatarURL helper to external tests.
func GravatarURL(value string) string {
	return gravatarURL(value)
}
