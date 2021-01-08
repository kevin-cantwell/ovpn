package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/pquerna/otp/vpn"
	"golang.org/x/crypto/ssh/terminal"
)

type flagSet struct {
	flags *flag.FlagSet
	args  []string
}

func NewFlagSet(name string, args []string, help string) *flagSet {
	flags := flag.NewFlagSet(name, flag.ExitOnError)
	flags.Usage = func() {
		fmt.Println(help)
	}
	return &flagSet{
		flags: flags,
		args:  args,
	}
}

func (fs *flagSet) StringVar(p *string, long, short, value string) {
	fs.flags.StringVar(p, long, value, "")
	fs.flags.StringVar(p, short, value, "")
}

func (fs *flagSet) BoolVar(p *bool, long, short string, value bool) {
	fs.flags.BoolVar(p, long, value, "")
	fs.flags.BoolVar(p, short, value, "")
}

func (fs *flagSet) Parse() error {
	return fs.flags.Parse(fs.args)
}

func (fs *flagSet) Arg(i int) string {
	return fs.flags.Arg(i)
}

func (fs *flagSet) Args() []string {
	return fs.flags.Args()
}

func (fs *flagSet) ExitHelp(code int) {
	fs.flags.Usage()
	os.Exit(code)
}

func main() {
	var (
		help bool
	)

	app := NewFlagSet("vpn", os.Args[1:], `
Usage:
  ovpn [COMMAND]

Commands:
  add          Add an open vpn config.
  code         Generate a vpn code.
  tunnelblick  Connect to a Tunnelblick VPN configuration.

Flags:
  help,h  Show this help.
`)
	app.BoolVar(&help, "help", "h", false)
	app.Parse()

	if help {
		app.ExitHelp(0)
	}

	switch cmd := app.Arg(0); cmd {
	case "add":
		var (
			issuer   string
			username string
			secret   string
			help     bool
		)

		flags := NewFlagSet(cmd, app.Args()[1:], `
Usage:
  vpn add [FLAGS]

Flags:
  issuer,i    Issuer name.
  username,u  Username.
  secret,s    Secret vpn key.
  help,h      Show this help.
`)
		flags.StringVar(&issuer, "issuer", "i", "")
		flags.StringVar(&username, "username", "u", "")
		flags.StringVar(&secret, "secret", "s", "")
		flags.BoolVar(&help, "help", "h", false)
		flags.Parse()

		if help {
			flags.ExitHelp(0)
		}

		if issuer == "" {
			fmt.Print("issuer: ")
			if _, err := fmt.Fscanln(os.Stdin, &issuer); err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		}
		if username == "" {
			fmt.Print("username: ")
			if _, err := fmt.Fscanln(os.Stdin, &username); err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		}
		if secret == "" {
			fmt.Print("secret: ")
			pw, err := terminal.ReadPassword(int(os.Stdin.Fd()))
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			fmt.Println()
			secret = string(pw)
		}

		cmd := exec.Command("/usr/bin/security", "add-generic-password",
			"-U", // update in place
			"-s", fmt.Sprintf("%s:%s", issuer, username),
			"-l", issuer,
			"-a", "password",
			"-D", "vpn",
			"-w", secret,
		)
		if err := cmd.Run(); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	case "code":
		var (
			issuer   string
			username string
			help     bool
		)
		flags := NewFlagSet(cmd, app.Args()[1:], `
Usage:
  vpn code [FLAGS]

Flags:
  issuer,i    Issuer name.
  username,u  Username.
  help,h      Show this help.
`)
		flags.StringVar(&issuer, "issuer", "i", "")
		flags.StringVar(&username, "username", "u", "")
		flags.BoolVar(&help, "help", "h", false)
		flags.Parse()

		if help {
			flags.ExitHelp(0)
		}

		if issuer == "" {
			fmt.Print("issuer: ")
			if _, err := fmt.Fscanln(os.Stdin, &issuer); err != nil {
				panic(err)
			}
		}

		cmd := exec.Command("/usr/bin/security", "find-generic-password",
			"-l", issuer,
			"-a", "password",
			"-D", "vpn",
			"-w", // print only the password
		)
		secret, err := cmd.Output()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		code, err := vpn.GenerateCode(string(secret), time.Now())
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		if terminal.IsTerminal(int(os.Stdout.Fd())) {
			fmt.Println(code)
		} else {
			fmt.Print(code)
		}
	case "tunnelblick":
		var (
			configName string
			username   string
			password   string
			help       bool
		)
		flags := NewFlagSet(cmd, app.Args()[1:], `
Usage:
  vpn tunnelblick [FLAGS]

Flags:
  name,n      VPN configuration name.
  username,u  Username.
  password,p  Password or vpn code.
  help,h      Show this help.
`)
		flags.StringVar(&configName, "name", "n", "")
		flags.StringVar(&username, "username", "u", "")
		flags.StringVar(&password, "password", "p", "")
		flags.BoolVar(&help, "help", "h", false)
		flags.Parse()

		if help {
			flags.ExitHelp(0)
		}

		if err := exec.Command("/usr/bin/security", "add-generic-password",
			"-U", // update in place
			"-s", "Tunnelblick-Auth-"+configName,
			"-a", "username",
			"-D", "application password",
			"-T", "/Applications/Tunnelblick.app",
			"-w", username,
		).Run(); err != nil {
			panic(err)
		}

		if err := exec.Command("/usr/bin/security", "add-generic-password",
			"-U", // update in place
			"-s", "Tunnelblick-Auth-"+configName,
			"-a", "password",
			"-D", "application password",
			"-T", "/Applications/Tunnelblick.app",
			"-w", password,
		).Run(); err != nil {
			panic(err)
		}

		if err := exec.Command("osascript",
			"-e", fmt.Sprintf(`Tell app "Tunnelblick" to connect "%s"`, configName),
		).Run(); err != nil {
			panic(err)
		}
	default:
		app.ExitHelp(1)
	}
}
