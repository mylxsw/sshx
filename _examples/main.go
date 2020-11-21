package main

import (
	"context"
	"log"
	"time"

	"github.com/mylxsw/sshx"
)

func main() {
	privateKeyConf := sshx.Credential{User: "root", PrivateKeyPath: "/Users/mylxsw/.ssh/id_rsa"}

	rs, err := sshx.NewClient("192.168.1.225:22", privateKeyConf, sshx.SetEstablishTimeout(10*time.Second), sshx.SetLogger(sshx.DefaultLogger{}))
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
		if err != nil {
			return err
		}

		psef, err := sub.Command(ctx, "ps -ef", sshx.RequestPty(120, 100))
		log.Printf("ps ef: %s", string(psef))
		return err
	}); err != nil {
		panic(err)
	}
}
