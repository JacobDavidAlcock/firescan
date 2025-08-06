package ui

import (
	"fmt"
	"io"
	"strings"

	"firescan/internal/types"

	"github.com/chzyer/readline"
)

// PrintBanner prints the ASCII art banner exactly as in original
func PrintBanner() {
	asciiArt := "                                                /===-_---~~~~~~~~~------____\n" +
		"                                               |===-~___                _,-'\n" +
		"                 -==\\\\                         `//~\\\\   ~~~~`---.___.-~~\n" +
		"             ______-==|                         | |  \\\\           _-~`\n" +
		"       __--~~~  ,-/-==\\\\                        | |   `\\        ,'\n" +
		"    _-~       /'    |  \\\\                      / /      \\      /\n" +
		"  .'        /       |   \\\\                   /' /        \\   /'\n" +
		" /  ____  /         |    `\\.__/-~~ ~ \\ _ _/'  /          \\/'\n" +
		"/-'~    ~~~~~---__  |     ~-/~         ( )   /'        _--~`\n" +
		"                  \\_|      /        _)   ;  ),   __--~~\n" +
		"                    '~~--_/      _-~/-  / \\   '-~ \\\n" +
		"                   {\\__--_/}    / \\\\_>- )<__\\      \\\n" +
		"                   /'   (_/  _-~  | |__>--<__|      |\n" +
		"                  |0  0 _/) )-~     | |__>--<__|      |\n" +
		"                  / /~ ,_/       / /__>---<__/      |\n" +
		"                 o o _//        /-~_>---<__-~      /\n" +
		"                 (^(~          /~_>---<__-      _-~\n" +
		"                ,/|           /__>--<__/     _-~\n" +
		"             ,//('(          |__>--<__|     /                  .----_\n" +
		"            ( ( '))          |__>--<__|    |                 /' _---_~\\\n" +
		"         `-)) )) (           |__>--<__|    |               /'  /     ~\\`\\\n" +
		"        ,/,'//( (             \\__>--<__\\    \\            /'  //        ||\n" +
		"      ,( ( ((, ))              ~-__>--<_~-_  ~--____---~' _/'/        /'\n" +
		"    `~/  )` ) ,/|                 ~-_~>--<_/-__       __-~ _/\n" +
		"  ._-~//( )/ )) `                    ~~-'_/_/ /~~~~~~~__--~\n" +
		"   ;'( ')/ ,)(                              ~~~~~~~~~~\n" +
		"  ' ') '( (/\n" +
		"    '   '  `"

	fireScanLogo := `
███████╗██╗██████╗ ███████╗███████╗ ██████╗ █████╗ ███╗   ██╗
██╔════╝██║██╔══██╗██╔════╝██╔════╝██╔════╝██╔══██╗████╗  ██║
█████╗  ██║██████╔╝█████╗  ███████╗██║     ███████║██╔██╗ ██║
██╔══╝  ██║██╔══██╗██╔══╝  ╚════██║██║     ██╔══██║██║╚██╗██║
██║     ██║██║  ██║███████╗███████║╚██████╗██║  ██║██║ ╚████║
╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝

              🔥 Firebase Security Auditor 🔥
`
	fmt.Println(types.ColorCyan + asciiArt + types.ColorReset)
	fmt.Println(types.ColorCyan + fireScanLogo + types.ColorReset)
}

// PrintHelp prints the help menu exactly as in original
func PrintHelp() {
	fmt.Println("\n--- FireScan Help Menu ---")
	fmt.Println("  set <var> <val>       Set a configuration variable (projectID, apiKey, token).")
	fmt.Println("  show options          Display the current configuration.")
	fmt.Println("  auth                  Authenticate to Firebase.")
	fmt.Println("    --create-account      Create/use a test account (defaults to fire@scan.com).")
	fmt.Println("    --email <email>       Email for account creation (use with --create-account).")
	fmt.Println("    -e <email>            Email for authentication.")
	fmt.Println("    -P <password>         Password for authentication.")
	fmt.Println("    logout                Clear the current session token.")
	fmt.Println("    show-token            Display the current JWT authentication token.")
	fmt.Println("    status                Show current authentication status and user details.")
	fmt.Println("    refresh               Manually refresh the authentication token.")
	fmt.Println("    --enum-providers      List enabled authentication providers.")
	fmt.Println("  scan                  Run a scan with the current configuration.")
	fmt.Println("    --all                 Run all scan modules with the 'all' wordlist.")
	fmt.Println("    -l <list>             Wordlist: all, users, config, passwords, functions, database, storage, security, or file path.")
	fmt.Println("    --rtdb                Scan Realtime Database.")
	fmt.Println("    --firestore           Scan Firestore.")
	fmt.Println("    --storage             Scan Cloud Storage.")
	fmt.Println("    --functions           Scan Cloud Functions.")
	fmt.Println("    --hosting             Scan Hosting for public config.")
	fmt.Println("    --rules               Test security rules (requires test mode).")
	fmt.Println("    --write               Test write access (requires test mode).")
	fmt.Println("    --services            Enumerate Firebase services.")
	fmt.Println("    --appcheck            Test App Check security.")
	fmt.Println("    --authattack          Advanced auth attacks (requires test mode).")
	fmt.Println("    --unauth              Unauthenticated access testing (adapts to available credentials).")
	fmt.Println("    --storage-sec         Firebase Storage deep security testing.")
	fmt.Println("    --mgmt-api            Firebase Management API security testing.")
	fmt.Println("    --rtdb-advanced       RTDB advanced rule context testing.")
	fmt.Println("    --fcm                 FCM & Push Notification security testing.")
	fmt.Println("    --probe               Safe mode - read-only operations (default).")
	fmt.Println("    --test                Test mode - write testing with cleanup.")
	fmt.Println("    --audit               Audit mode - deep testing with confirmation.")
	fmt.Println("    --json                Output results in JSON format.")
	fmt.Println("    -c <num>              Set concurrency level.")
	fmt.Println("  extract               Dump data from a readable path.")
	fmt.Println("    --firestore --path <collection>")
	fmt.Println("    --rtdb --path <node>")
	fmt.Println("  wordlist <cmd> [opts] Manage wordlists for the current session.")
	fmt.Println("    show                  List available built-in wordlists.")
	fmt.Println("    show <name>           Show contents of a specific list.")
	fmt.Println("    add <name> <w1,w2>    Add a new session-only list.")
	fmt.Println("  make-config           Print an example configuration file.")
	fmt.Println("  save-quit             Save current session and exit.")
	fmt.Println("  help                  Display this help menu.")
	fmt.Println("  exit / quit           Close the application.")
	fmt.Println("\nStartup Options:")
	fmt.Println("  firescan --config <file>    Load configuration from YAML file")
	fmt.Println("  firescan --resume           Resume from a saved session")
	fmt.Println("--------------------------")
}

// RunConsole runs the interactive console exactly as in original
func RunConsole() error {
	// Setup readline for a professional console experience.
	completer := readline.NewPrefixCompleter(
		readline.PcItem("set",
			readline.PcItem("projectid"),
			readline.PcItem("apikey"),
			readline.PcItem("token"),
		),
		readline.PcItem("show",
			readline.PcItem("options"),
		),
		readline.PcItem("auth",
			readline.PcItem("--create-account"),
			readline.PcItem("--email"),
			readline.PcItem("-e"),
			readline.PcItem("-P"),
			readline.PcItem("logout"),
			readline.PcItem("show-token"),
			readline.PcItem("--enum-providers"),
			readline.PcItem("status"),
			readline.PcItem("refresh"),
		),
		readline.PcItem("scan",
			readline.PcItem("--all"),
			readline.PcItem("-l",
				readline.PcItem("all"),
				readline.PcItem("users"),
				readline.PcItem("config"),
				readline.PcItem("passwords"),
				readline.PcItem("functions"),
				readline.PcItem("database"),
				readline.PcItem("storage"),
				readline.PcItem("security"),
			),
			readline.PcItem("--rtdb"),
			readline.PcItem("--firestore"),
			readline.PcItem("--storage"),
			readline.PcItem("--functions"),
			readline.PcItem("--hosting"),
			readline.PcItem("--rules"),
			readline.PcItem("--write"),
			readline.PcItem("--services"),
			readline.PcItem("--appcheck"),
			readline.PcItem("--authattack"),
			readline.PcItem("--unauth"),
			readline.PcItem("--storage-sec"),
			readline.PcItem("--mgmt-api"),
			readline.PcItem("--rtdb-advanced"),
			readline.PcItem("--fcm"),
			readline.PcItem("--probe"),
			readline.PcItem("--test"),
			readline.PcItem("--audit"),
			readline.PcItem("--json"),
			readline.PcItem("-c"),
		),
		readline.PcItem("extract",
			readline.PcItem("--firestore"),
			readline.PcItem("--rtdb"),
			readline.PcItem("--path"),
		),
		readline.PcItem("wordlist",
			readline.PcItem("show"),
			readline.PcItem("add"),
		),
		readline.PcItem("make-config"),
		readline.PcItem("save-quit"),
		readline.PcItem("help"),
		readline.PcItem("exit"),
		readline.PcItem("quit"),
	)

	rl, err := readline.NewEx(&readline.Config{
		Prompt:          "firescan > ",
		HistoryFile:     "/tmp/firescan_history.tmp",
		AutoComplete:    completer,
		InterruptPrompt: "^C",
		EOFPrompt:       "exit",
	})
	if err != nil {
		return err
	}
	defer rl.Close()

	// This is the main REPL (Read-Evaluate-Print Loop).
	for {
		line, err := rl.Readline()
		if err == readline.ErrInterrupt || err == io.EOF {
			break
		}

		input := strings.Fields(line)
		if len(input) == 0 {
			continue
		}

		command := input[0]
		args := input[1:]

		switch strings.ToLower(command) {
		case "set":
			HandleSet(args)
		case "show":
			HandleShow(args)
		case "auth":
			HandleAuth(args)
		case "scan":
			HandleScan(args)
		case "extract":
			HandleExtract(args)
		case "wordlist":
			HandleWordlist(args)
		case "make-config":
			HandleMakeConfig()
		case "save-quit":
			HandleSaveQuit()
			return nil
		case "help":
			PrintHelp()
		case "exit", "quit":
			return nil
		default:
			fmt.Println("❌ Unknown command. Type 'help' for a list of commands.")
		}
	}
	return nil
}