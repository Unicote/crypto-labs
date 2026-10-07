package modes

func (r *runner) encryptECB(data []byte) ([]byte, error) {
	return r.transformBlocks(data, r.encryptBlock)
}

func (r *runner) decryptECB(data []byte) ([]byte, error) {
	return r.transformBlocks(data, r.decryptBlock)
}
