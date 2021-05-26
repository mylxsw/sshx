package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/mylxsw/sshx"
)

func main() {
	// 创建鉴权秘钥
	privateKeyConf := sshx.Credential{User: "root", PrivateKeyPath: "/home/mylxsw/.ssh/id_rsa"}

	// 创建 sshx 客户端
	rs, err := sshx.NewClient("192.168.1.225:22", privateKeyConf, sshx.SetEstablishTimeout(10*time.Second), sshx.SetLogger(sshx.DefaultLogger{}))
	if err != nil {
		panic(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := rs.Handle(func(sub sshx.EnhanceClient) error {
		if err := sub.TempSendFile("./bin/cmd-simulator", func(tempFilepath string) error {
			res, err := sub.Command(ctx, fmt.Sprintf("chmod +x ./%s && ./%s -stdout Hello -stderr 'This is an error' -return-code 3", tempFilepath, tempFilepath))
			if err != nil {
				return fmt.Errorf("%v: %v", err, string(res))
			}

			log.Printf("cmd-simulator: %v", string(res))
			return nil
		}); err != nil {
			return err
		}

		//whoami, err := sub.Command(ctx, "whoami")
		//if err != nil {
		//	return err
		//}
		//
		//log.Printf("whoami: %s", whoami)
		//
		//dataReader := strings.NewReader("Hello, world")
		//_, err = sub.WriteFileOverride("/root/test.txt", dataReader)
		//if err != nil {
		//	return err
		//}
		//
		//hello, err := sub.Command(ctx, "cat /root/test.txt")
		//if err != nil {
		//	return err
		//}
		//
		//log.Printf("res: %s", hello)
		//
		//if err := sub.Remove("/root/test.txt"); err != nil {
		//	return err
		//}
		//
		//psef, err := sub.Command(ctx, "ps -ef", sshx.RequestPty(120, 100))
		//if err != nil {
		//	return err
		//}
		//log.Printf("ps ef: %s", string(psef))
		//
		//if err := sub.TempWriteFile(strings.NewReader("Yes!"), func(tempFilepath string) error {
		//	log.Printf("temp file: %s", tempFilepath)
		//	res, err := sub.Command(context.TODO(), "cat "+tempFilepath)
		//	if err != nil {
		//		return err
		//	}
		//
		//	log.Printf("temp file content: %s", string(res))
		//
		//	return nil
		//}); err != nil {
		//	return err
		//}

		//if err := sub.SendDirectory("/root/temp", "/Users/mylxsw/codes/github/sshx"); err != nil {
		//	return err
		//}

		return nil
	}); err != nil {
		panic(err)
	}
}
