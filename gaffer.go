package main

type Gaffer struct {
}

func (c Config) Build() (*Gaffer, error) {
	g := &Gaffer{
	}
	return g, nil
}

