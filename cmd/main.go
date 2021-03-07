package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/dubs3c/SANDLADA/agent"
	"github.com/dubs3c/SANDLADA/server"
)

func main() {

	srvOpts := server.Options{}
	agentOpts := agent.Options{}
	agentMode := flag.NewFlagSet("agent", flag.ExitOnError)
	serverMode := flag.NewFlagSet("server", flag.ExitOnError)

	serverMode.StringVar(&srvOpts.Sample, "sample", "", "Malware sample to analyse")
	serverMode.StringVar(&srvOpts.Sample, "s", "", "Malware sample to analyse")
	serverMode.StringVar(&srvOpts.AgentVM, "agentVM", "", "VM to use for analysis, read from conffig file")
	serverMode.StringVar(&srvOpts.AgentVM, "vm", "", "VM to use for analysis, read from conffig file")
	serverMode.StringVar(&srvOpts.AgentIP, "agentIP", "", "IP of agent to send sample to")
	serverMode.StringVar(&srvOpts.AgentIP, "ip", "", "IP of agent to send sample to")
	serverMode.StringVar(&srvOpts.Database, "database", "~/.sandlada/sqlite.db", "Use local sqlite database for storing results. Default ~/.sandlada/sqlite.db")
	serverMode.StringVar(&srvOpts.Database, "d", "~/.sandlada/sqlite.db", "Use local sqlite database for storing results. Default ~/.sandlada/sqlite.db")
	serverMode.StringVar(&srvOpts.Config, "config", "~/.sandlada/config", "Configuration file to read from. Default ~/.sandlada/config")
	serverMode.StringVar(&srvOpts.Config, "c", "~/.sandlada/config", "Configuration file to read from. Default ~/.sandlada/config")
	serverMode.StringVar(&srvOpts.Result, "result", "~/.sandlada/result/", "Folder location to store analysis results in. Default ~/.sandlada/result")
	serverMode.StringVar(&srvOpts.Result, "r", "", "Folder location to store analysis results in. Default ~/.sandlada/result")
	serverMode.IntVar(&srvOpts.LocalPort, "lport", 9001, "Local port to listen on. Default 9001")
	serverMode.IntVar(&srvOpts.LocalPort, "lp", 9001, "Local port to listen on. Default 9001")

	agentMode.IntVar(&agentOpts.LocalPort, "lport", 9001, "Local port to listen on. Default 9001")
	agentMode.IntVar(&agentOpts.LocalPort, "lp", 9001, "Local port to listen on. Default 9001")
	agentMode.StringVar(&agentOpts.Server, "server", "", "Server IP to send data to")
	agentMode.StringVar(&agentOpts.Server, "s", "", "Server IP to send data to")

	flag.Usage = func() {
		h := "\nSANDLÅDA - The Dynamic Malware Analysis Lab\n\n"

		h += "Usage:\n"
		h += "  sandlada server|agent|version [options]\n\n"

		h += "Server options:\n"
		h += "  -s,     --sample    " + serverMode.Lookup("sample").Usage + "\n"
		h += "  -vm,    --agent-vm  " + serverMode.Lookup("agentVM").Usage + "\n"
		h += "  -ip,    --agent-ip  " + serverMode.Lookup("agentIP").Usage + "\n"
		h += "  -r,     --result    " + serverMode.Lookup("result").Usage + "\n"
		h += "  -db,    --database  " + serverMode.Lookup("database").Usage + "\n"
		h += "  -c,     --config    " + serverMode.Lookup("config").Usage + "\n"
		h += "  -lp,    --lport     " + agentMode.Lookup("lport").Usage + "\n"
		h += "\nAgent options:\n"
		h += "  -srv,   --server    " + agentMode.Lookup("server").Usage + "\n"
		h += "  -lp,    --lport     " + agentMode.Lookup("lport").Usage + "\n"
		h += "\nVersion: Print version\n"

		h += "\nExamples:\n"
		h += "  sandlada server -s malware.py -vm trinity -lp 9001\n"
		h += "  sandlada agent --server 192.168.1.25:9001 --lport 9001\n"
		h += "  sandlada version\n\n"

		fmt.Fprintf(os.Stderr, h)
	}

	agentMode.Usage = func() {
		h := "\nAgent usage:\n"
		h += "  sandlada agent [options]\n\n"
		h += "Agent options:\n"
		h += "  -s,   --server    Server IP to send data to\n"
		h += "  -lp,  --lport     Port to listen on\n"
		h += "\nExamples:\n"
		h += "  sandlada agent --server 192.168.1.25:9001 --lport 9001\n"

		fmt.Fprintf(os.Stderr, h)
	}

	serverMode.Usage = func() {
		h := "\nUsage:\n"
		h += "  sandlada server [options]\n\n"

		h += "Server options:\n"
		h += "  -s,     --sample    Malware sample to analyse\n"
		h += "  -vm,    --agent-vm  VM to use for analysis\n"
		h += "  -ip,    --agent-ip  IP of agent to send sample to\n"
		h += "  -r,     --result    Folder location to store analysis results in. Default ~/.sandlada/result\n"
		h += "  -db,    --database  Use local sqlite database for storing results\n"
		h += "  -c,     --config    Configuration file to read from\n"
		h += "  -lp,    --lport     Port to listen on\n"

		h += "\nExamples:\n"
		h += "  sandlada server -s malware.py -vm trinity -lp 9001\n"

		fmt.Fprintf(os.Stderr, h)
	}

	if len(os.Args) <= 1 {
		flag.Usage()
		os.Exit(0)
	}

	switch os.Args[1] {
	case "server":
		log.Println("You entered server")
		serverMode.Parse(os.Args[2:])
	case "agent":
		log.Println("You entered agent")
		agentMode.Parse(os.Args[2:])
	case "version":
		fmt.Println("Version 0.5")
		os.Exit(0)
	default:
		fmt.Printf("%q is not valid command.\n", os.Args[1])
		os.Exit(2)
	}

	if serverMode.Parsed() {
		server.StartServer(srvOpts)
	}

	if agentMode.Parsed() {
		agent.StartAgent()
	}

}
