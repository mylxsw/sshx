package main

import (
	"context"
	"time"

	"log"

	"github.com/mylxsw/sshx"
)

func main() {
	privateKeyConf := sshx.Credential{User: "root", PrivateKeyPath: "/Users/mylxsw/.ssh/id_rsa"}

	rs, err := sshx.NewClient("10.0.0.2:22", privateKeyConf, sshx.SetEstablishTimeout(10*time.Second), sshx.SetLogger(sshx.DefaultLogger{}))
	if err != nil {
		panic(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := rs.Handle(func(sub sshx.Client) error {
		whoami, err := sub.Command(ctx, "whoami")
		if err != nil {
			return err
		}

		log.Printf("whoami: %s", whoami)

		_, err = sub.SendFile("/root/test.txt", "/Users/mylxsw/Downloads/test.txt", true, true)
		if err != nil {
			return err
		}

		_, err = sub.Command(ctx, "cat /root/test.txt && rm -f /root/test.txt")
		return err
	}); err != nil {
		panic(err)
	}
}
