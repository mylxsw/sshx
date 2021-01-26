package main

import (
	"context"
	"log"
	"strings"
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

	if err := rs.Handle(func(sub sshx.EnhanceClient) error {
		whoami, err := sub.Command(ctx, "whoami")
		if err != nil {
			return err
		}

		log.Printf("whoami: %s", whoami)

		dataReader := strings.NewReader("Hello, world")
		_, err = sub.WriteFileOverride("/root/test.txt", dataReader)
		if err != nil {
			return err
		}

		hello, err := sub.Command(ctx, "cat /root/test.txt")
		if err != nil {
			return err
		}

		log.Printf("res: %s", hello)

		if err := sub.Remove("/root/test.txt"); err != nil {
			return err
		}

		psef, err := sub.Command(ctx, "ps -ef", sshx.RequestPty(120, 100))
		if err != nil {
			return err
		}
		log.Printf("ps ef: %s", string(psef))

		if err := sub.TempWriteFile(strings.NewReader("Yes!"), func(tempFilepath string) error {
			log.Printf("temp file: %s", tempFilepath)
			res, err := sub.Command(context.TODO(), "cat "+tempFilepath)
			if err != nil {
				return err
			}

			log.Printf("temp file content: %s", string(res))

			return nil
		}); err != nil {
			return err
		}

		//if err := sub.SendDirectory("/root/temp", "/Users/mylxsw/codes/github/sshx"); err != nil {
		//	return err
		//}

		return nil
	}); err != nil {
		panic(err)
	}
}
