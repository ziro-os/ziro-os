package cmd

// Public keys of the official catalogs (ed25519, PKIX PEM). The private halves are the
// ZIRO_CATALOG_KEY secrets of github.com/ziro-os/pkgs and github.com/ziro-os/apps. Rotating a key
// means shipping a ziroctl release with the new public key before the catalog is re-signed.
const (
	pkgsCatalogKey = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEADzQQC8u9SDgzt6g29N4rsJs/F7bAATPX9fKlIHkRcUQ=
-----END PUBLIC KEY-----
`
	appsCatalogKey = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAGLxP1OniNx8JMLvQnZefHTCRdaFSKmbtS4+VLy6L938=
-----END PUBLIC KEY-----
`
)
