package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/dubs3c/SANDLADA/agent"
	"github.com/dubs3c/SANDLADA/server"
)

func main() {

	srvOpts := server.Options{}
	agentOpts := agent.Options{}
	agentMode := flag.NewFlagSet("agent", flag.ExitOnError)
	serverMode := flag.NewFlagSet("server", flag.ExitOnError)
	userHomeDir, _ := os.UserHomeDir()
	sandladaDir := userHomeDir + "/.sandlada"
	configIni := userHomeDir + "/.sandlada/config.ini"
	resultDir := sandladaDir + "/result"

	serverMode.StringVar(&srvOpts.Sample, "sample", "", "Malware sample to analyse")
	serverMode.StringVar(&srvOpts.Sample, "s", "", "Malware sample to analyse")
	serverMode.StringVar(&srvOpts.AgentVM, "agentVM", "", "VM to use for analysis, read from conffig file")
	serverMode.StringVar(&srvOpts.AgentVM, "vm", "", "VM to use for analysis, read from conffig file")
	serverMode.StringVar(&srvOpts.AgentIP, "agentIP", "", "IP of agent to send sample to")
	serverMode.StringVar(&srvOpts.AgentIP, "ip", "", "IP of agent to send sample to")
	serverMode.StringVar(&srvOpts.Database, "database", "~/.sandlada/sqlite.db", "Use local sqlite database for storing results. Default ~/.sandlada/sqlite.db")
	serverMode.StringVar(&srvOpts.Database, "d", "~/.sandlada/sqlite.db", "Use local sqlite database for storing results. Default ~/.sandlada/sqlite.db")
	serverMode.StringVar(&srvOpts.Config, "config", configIni, "Configuration file to read from. Default ~/.sandlada/config.ini")
	serverMode.StringVar(&srvOpts.Config, "c", configIni, "Configuration file to read from. Default ~/.sandlada/config.ini")
	serverMode.StringVar(&srvOpts.Result, "result", resultDir, "Folder location to store analysis results in. Default ~/.sandlada/result")
	serverMode.StringVar(&srvOpts.Result, "r", resultDir, "Folder location to store analysis results in. Default ~/.sandlada/result")
	serverMode.StringVar(&srvOpts.Executor, "executor", "", "Run malware with specific command, e.g. \"python2.7\"")
	serverMode.StringVar(&srvOpts.Executor, "e", "", "Run malware with specific command, e.g. \"python2.7\"")
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
		h += "  -e,     --executor  " + serverMode.Lookup("executor").Usage + "\n"
		h += "  -db,    --database  " + serverMode.Lookup("database").Usage + "\n"
		h += "  -c,     --config    " + serverMode.Lookup("config").Usage + "\n"
		h += "  -lp,    --lport     " + agentMode.Lookup("lport").Usage + "\n"
		h += "\nAgent options:\n"
		h += "  -srv,   --server    " + agentMode.Lookup("server").Usage + "\n"
		h += "  -lp,    --lport     " + agentMode.Lookup("lport").Usage + "\n"
		h += "\nVersion: Print version\n"

		h += "\nExamples:\n"
		h += "  sandlada server -s malware.py -e python2 -vm trinity -lp 9001\n"
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
		if err := serverMode.Parse(os.Args[2:]); err != nil {
			fmt.Println("Someting went wrong parsing server options, error: ", err)
		}
		break
	case "agent":
		if err := agentMode.Parse(os.Args[2:]); err != nil {
			fmt.Println("Someting went wrong parsing agent options, error:", err)
		}
		break
	case "version":
		fmt.Println("Version 0.5")
		os.Exit(0)
	default:
		fmt.Printf("%q is not valid command.\n", os.Args[1])
		os.Exit(2)
	}

	if serverMode.Parsed() {
		if srvOpts.Sample == "" {
			fmt.Println("Please specify a malware sample to analyse")
			os.Exit(1)
		}

		if srvOpts.AgentIP == "" && srvOpts.AgentVM == "" || srvOpts.AgentIP != "" && srvOpts.AgentVM != "" {
			fmt.Println("Please specify a either a VM or an IP for the analysis machine")
			os.Exit(1)
		}

		server.StartServer(srvOpts)
	}

	if agentMode.Parsed() {

		if agentOpts.Server == "" {
			fmt.Println("Please specify a collection server")
			os.Exit(1)
		}

		agent.StartAgent(agentOpts)
	}
}
