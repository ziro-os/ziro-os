package cmd

// The built-in WAF rule catalog. Rule IDs are stable: they appear in logs, metrics and
// exclusions, so a rule may be refined but its ID keeps its meaning.
//
// Every regular expression is matched against normalized text (see wafNormalize): percent-decoded
// up to twice, lower case, white space collapsed to single spaces, comments replaced by a space.
// Patterns are therefore written in lower case. Needles are the literals a value must contain
// before its rule's expression is worth running; they come from the same normalized text. Values
// in one buffer are separated by \x01, which no pattern matches across.

type wafGroup uint8

const (
	gSQLi wafGroup = iota
	gXSS
	gLFI
	gRCE
	gJava
	gXXE
	gSSRF
	gProtocol
	gScanner
	numWAFGroups
)

var wafGroupNames = [numWAFGroups]string{"sqli", "xss", "lfi", "rce", "java", "xxe", "ssrf", "protocol", "scanner"}

// Request parts a rule inspects.
const (
	tPath uint8 = 1 << iota
	tArgs
	tCookies
	tHeaders
	tBody
	tUA
	numWAFTargets = 6

	tPayload    = tPath | tArgs | tCookies | tBody // where user-supplied content travels
	tEverywhere = tPayload | tHeaders
)

// Severity scores, as in the OWASP Core Rule Set.
const (
	scoreCritical = 5
	scoreError    = 4
	scoreWarning  = 3
	scoreNotice   = 2
)

type wafRuleDef struct {
	ID      string
	Group   wafGroup
	Level   int // 1 precise ... 3 paranoid
	Score   int
	Msg     string
	Targets uint8
	Needles []string // lower-case literals; one must appear for Re to run
	Re      string   // RE2; empty for rules implemented in code (the protocol checks)
}

var wafCatalog = []wafRuleDef{
	// ---- SQL injection ----
	{"ZW-942100", gSQLi, 1, scoreCritical, "SQL injection: UNION SELECT", tPayload,
		[]string{"union"}, `\bunion\b[\s(]*(?:all[\s(]+|distinct[\s(]+)?select\b`},
	{"ZW-942110", gSQLi, 1, scoreCritical, "SQL injection: quote followed by a boolean tautology", tPayload,
		[]string{"' or", "' and", "\" or", "\" and", "'or", "\"or", "'||", "\"||", "'&&", "' ||", "' &&"},
		`['"]\s*(?:or|and|\|\||&&)\s*['"(]?[\w.]*['"]?\s*(?:=|<>|!=|<|>|like\b|is\b|in\b|between\b)`},
	{"ZW-942120", gSQLi, 2, scoreError, "SQL injection: numeric tautology", tPayload,
		[]string{"or 1", "and 1", "or 0", "and 0", "1=1", "1 = 1", "or true", "and true", "or false", "and false", "or '", "and '", "or \"", "and \""},
		`\b(?:or|and)\s+(?:\d+|true|false|'[^'\x01]*'|"[^"\x01]*")\s*(?:=|<>|!=|like\b)\s*(?:\d+|true|false|'[^'\x01]*'|"[^"\x01]*")|\b1\s*=\s*1\b`},
	{"ZW-942130", gSQLi, 1, scoreCritical, "SQL injection: stacked statement", tPayload,
		[]string{"; drop", ";drop", "; select", ";select", "; insert", ";insert", "; update", ";update", "; delete", ";delete",
			"; exec", ";exec", "; shutdown", ";shutdown", "; truncate", ";truncate", "; alter", ";alter", "; create", ";create",
			"; declare", ";declare", "; waitfor", ";waitfor"},
		`;\s*(?:drop|select|insert|update|delete|exec|execute|shutdown|truncate|alter|create|declare|waitfor)\b`},
	{"ZW-942140", gSQLi, 1, scoreWarning, "SQL injection: comment after a quote", tPayload,
		[]string{"'--", "' --", "\"--", "\" --", "'#", "' #", "'/*", "' /*", ")--", ") --", ")#"},
		`['"]\)*\s*(?:--|#|/\*)`},
	{"ZW-942150", gSQLi, 1, scoreCritical, "SQL injection: database function or catalog", tPayload,
		[]string{"sleep", "benchmark", "waitfor", "load_file", "extractvalue", "updatexml", "xp_cmdshell", "into outfile", "into dumpfile",
			"information_schema", "sysobjects", "sys.databases", "sys.tables", "mysql.user", "@@version", "group_concat"},
		`\b(?:sleep\s*\(\s*\d+\s*\)|pg_sleep\s*\(|benchmark\s*\(\s*\d+\s*,|waitfor\s+delay\s+['"]|load_file\s*\(|extractvalue\s*\(|updatexml\s*\(|xp_cmdshell|into\s+(?:out|dump)file)|information_schema\s*\.|@@version|\bsys\.(?:databases|tables|objects)\b|\bmysql\.user\b|\bgroup_concat\s*\(`},
	{"ZW-942160", gSQLi, 3, scoreWarning, "SQL: statement keywords in free text", tPayload,
		[]string{"select", "insert into", "delete from", "drop table", "drop database", "update"},
		`\bselect\b[^\x01]{1,120}?\bfrom\b|\binsert\s+into\b|\bdelete\s+from\b|\bdrop\s+(?:table|database)\b|\bupdate\b[^\x01]{1,60}?\bset\b`},
	{"ZW-942170", gSQLi, 2, scoreError, "SQL injection: column probing", tPayload,
		[]string{"order by", "group by", "having", "limit "},
		`\b(?:order|group)\s+by\s+\d+|\bhaving\s+\d+\s*=|\blimit\s+\d+\s*,\s*\d+\s*(?:--|#|$)`},
	{"ZW-942180", gSQLi, 2, scoreWarning, "SQL injection: long hex literal", tPayload,
		[]string{"0x"}, `\b0x[0-9a-f]{8,}\b`},

	// ---- cross-site scripting ----
	{"ZW-941100", gXSS, 1, scoreCritical, "XSS: script tag", tPayload,
		[]string{"<script", "</script", "< script"}, `<\s*/?\s*script\b`},
	{"ZW-941110", gXSS, 1, scoreCritical, "XSS: event handler attribute", tPayload,
		[]string{"onerror", "onload", "onclick", "onmouse", "onfocus", "onblur", "onkey", "onsubmit", "onchange", "oninput", "ontoggle", "onstart",
			"onbegin", "onpageshow", "onanimation", "onpointer", "ondrag", "ondrop", "onwheel", "oncopy", "onpaste", "onresize", "onscroll", "onplay"},
		`\bon(?:error|load|click|mouse\w+|focus\w*|blur|key\w+|submit|change|input|toggle|start|begin|pageshow|animation\w+|pointer\w+|drag\w*|drop|wheel|copy|paste|resize|scroll|play)\s*=`},
	{"ZW-941120", gXSS, 1, scoreError, "XSS: script URI", tPayload,
		[]string{"javascript", "vbscript", "data:"}, `\b(?:javascript|vbscript)\s*:|\bdata\s*:\s*text/html`},
	{"ZW-941130", gXSS, 1, scoreCritical, "XSS: embedding tag", tPayload,
		[]string{"<iframe", "<object", "<embed", "<svg", "<math", "<base", "<applet"}, `<\s*(?:iframe|object|embed|svg|math|base|applet)\b`},
	{"ZW-941140", gXSS, 2, scoreError, "XSS: markup tag", tPayload,
		[]string{"<img", "<body", "<link", "<meta", "<style", "<form", "<video", "<audio", "<details", "<marquee", "<input", "<button", "<textarea"},
		`<\s*(?:img|body|link|meta|style|form|video|audio|details|marquee|input|button|textarea)\b[^>\x01]*>`},
	{"ZW-941150", gXSS, 2, scoreError, "XSS: CSS expression or binding", tPayload,
		[]string{"expression", "-moz-binding", "@import", "behavior"}, `\bexpression\s*\(|-moz-binding|@import\s+(?:url|["'])|\bbehavior\s*:\s*url`},
	{"ZW-941160", gXSS, 2, scoreError, "XSS: script sink", tPayload,
		[]string{"document.", "window.", "eval", "alert", "prompt", "confirm", "fromcharcode"},
		`\bdocument\s*\.\s*(?:cookie|write|domain|location)|\bwindow\s*\.\s*(?:location|name)|\beval\s*\(|\balert\s*\(|\bprompt\s*\(|\bconfirm\s*\(|fromcharcode`},

	// ---- path traversal and local file inclusion ----
	{"ZW-930100", gLFI, 1, scoreCritical, "Path traversal", tPayload,
		[]string{"../", "..\\", "..;/"}, `(?:^|[/\\\x01])\.\.(?:[/\\;]|$|\x01)`},
	{"ZW-930110", gLFI, 1, scoreCritical, "Access to a sensitive file", tPayload,
		[]string{"/etc/", "/proc/", "boot.ini", "win.ini", "/windows/system32", "/.env", ".git/", "/.ssh/", "id_rsa", ".htpasswd",
			"wp-config.php", "web-inf/", ".aws/credentials"},
		`/etc/(?:passwd|shadow|group|hosts|issue|sudoers)|/proc/(?:self|\d+|version|cmdline)|\bboot\.ini\b|\bwin\.ini\b|/windows/system32|(?:^|/)\.env(?:\.|$|\x01)|\.git/(?:config|head)|/\.ssh/|\bid_rsa\b|\.htpasswd|wp-config\.php|web-inf/|\.aws/credentials`},
	{"ZW-930120", gLFI, 1, scoreCritical, "Stream wrapper", tPayload,
		[]string{"php://", "file://", "expect://", "zip://", "phar://", "glob://", "compress.zlib://", "ssh2://", "ogg://", "rar://"},
		`\b(?:php|file|expect|zip|phar|glob|compress\.zlib|rar|ogg|ssh2)://`},

	// ---- remote command and code execution ----
	{"ZW-932100", gRCE, 1, scoreCritical, "Command injection: shell command after a separator", tPayload,
		[]string{";", "|", "&&", "`", "$("},
		"(?:;|\\|\\|?|&&|`|\\$\\()\\s*(?:cat|ls|id|whoami|uname|wget|curl|nc|ncat|netcat|bash|sh|zsh|python[23]?|perl|ruby|php|node|rm|chmod|chown|ping|nslookup|dig|echo|sleep|env|printenv|nmap|telnet|ftp|tftp|powershell|cmd)\\b(?:\\s|$|\\x01|[;|&`)<>-])"},
	{"ZW-932110", gRCE, 1, scoreCritical, "Command injection: shell or interpreter path", tPayload,
		[]string{"/bin/", "/usr/bin/", "cmd.exe", "cmd /c", "powershell", "/dev/tcp/", "/dev/udp/"},
		`/bin/(?:ba|z|da|k|c|tc)?sh\b|/usr/bin/(?:env|python[23]?|perl|ruby|php|wget|curl|nc|ncat|bash)\b|\bcmd(?:\.exe)?\s*/c\b|\bpowershell(?:\.exe)?\s+-|/dev/(?:tcp|udp)/`},
	{"ZW-932120", gRCE, 1, scoreCritical, "Code injection: PHP open tag", tPayload,
		[]string{"<?"}, `<\?(?:php|=)`},
	{"ZW-932130", gRCE, 2, scoreError, "Code injection: dangerous function call", tPayload,
		[]string{"eval", "assert", "system", "passthru", "shell_exec", "popen", "proc_open", "pcntl_exec", "base64_decode", "create_function",
			"exec", "os.system", "os.popen", "subprocess", "child_process", "__import__", "runtime"},
		`\b(?:eval|assert|system|passthru|shell_exec|popen|proc_open|pcntl_exec|create_function|base64_decode|exec)\s*\(|\bos\.(?:system|popen)\b|\bsubprocess\.|\bchild_process\b|__import__\s*\(|\bruntime\s*\.\s*(?:getruntime\(\)\s*\.\s*)?exec`},
	{"ZW-932140", gRCE, 3, scoreWarning, "Template injection", tPayload,
		[]string{"{{", "${", "<%", "#{"}, `\{\{[^\x01]{1,80}?\}\}|\$\{[^}\x01]{1,80}\}|<%[=-]?[^\x01]{1,80}?%>|#\{[^}\x01]{1,80}\}`},
	{"ZW-932150", gRCE, 1, scoreCritical, "Shellshock", tHeaders | tCookies,
		[]string{"() {", "(){"}, `\(\)\s*\{`},

	// ---- Java ----
	{"ZW-944100", gJava, 1, scoreCritical, "Log4Shell / JNDI lookup", tEverywhere,
		[]string{"${", "jndi:"},
		`\$\{\s*(?:jndi|\$\{|lower:|upper:|::-|env:|sys:|java:|ctx:|date:|bundle:|main:|k8s:|docker:|spring:|web:|base64:)|jndi\s*:\s*(?:ldaps?|rmi|dns|iiop|nis|corba|https?)`},
	{"ZW-944110", gJava, 1, scoreCritical, "Java class loading, OGNL or serialized object", tEverywhere,
		[]string{"java.", "classloader", "runtime", "processbuilder", "(#", "%{", "@java", "ro0ab", "aced0005"},
		`\bjava\.lang\.(?:runtime|processbuilder|system|class)\b|\bjava\.io\.(?:objectinputstream|filereader|file)\b|class\.(?:module\.)?classloader|\bruntime\s*\.\s*getruntime|\bprocessbuilder\s*\(|\(#[a-z_]\w*\s*=|%\{#|@java\.|\bro0ab[a-z0-9+/]{6}|\baced0005`},

	// ---- XML external entities ----
	{"ZW-946100", gXXE, 1, scoreCritical, "XML external entity or DTD", tBody | tArgs,
		[]string{"<!entity", "<!doctype", "xi:include"}, `<!entity\b|<!doctype[^>\x01]*\[|<xi:include\b`},

	// ---- server-side request forgery ----
	{"ZW-934100", gSSRF, 1, scoreCritical, "Cloud metadata endpoint", tEverywhere,
		[]string{"169.254.", "metadata.google.internal", "100.100.100.200", "fd00:ec2", "metadata.azure", "instance-data"},
		`169\.254\.(?:169\.254|170\.2)|metadata\.google\.internal|100\.100\.100\.200|fd00:ec2::254|metadata\.azure\.com|\binstance-data\b`},
	{"ZW-934110", gSSRF, 1, scoreError, "Dangerous URL scheme", tPath | tArgs | tBody,
		[]string{"gopher://", "dict://", "ldap://", "ldaps://", "tftp://", "jar:", "netdoc://", "sftp://", "smb://"},
		`\b(?:gopher|dict|ldaps?|tftp|jar|netdoc|sftp|smb)://|\bjar:(?:https?|file)`},
	{"ZW-934120", gSSRF, 2, scoreError, "URL pointing at an internal address", tPath | tArgs | tBody,
		[]string{"://localhost", "://127.", "://0.0.0.0", "://[::", "://10.", "://192.168.", "://172.", "://0x7f", "://2130706433", "://0177", "@localhost", "@127."},
		`(?:https?|ftp)://(?:[^/@\x01]*@)?(?:localhost\b|127\.\d+\.\d+\.\d+|0\.0\.0\.0|0x7f[0-9a-f]*|2130706433|0177\.|\[::1?\]|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)`},

	// ---- scanners and probes ----
	{"ZW-913100", gScanner, 1, scoreCritical, "Known scanner or attack tool", tUA,
		[]string{"sqlmap", "nikto", "nessus", "acunetix", "nmap", "masscan", "wpscan", "dirbuster", "gobuster", "ffuf", "wfuzz", "havij",
			"netsparker", "burpcollaborator", "zgrab", "nuclei", "openvas", "w3af", "arachni", "metasploit", "hydra", "jaeles", "feroxbuster",
			"commix", "xsser", "skipfish", "whatweb", "appscan", "webinspect", "zaproxy", "owasp zap", "bsqlbf", "pangolin"},
		`sqlmap|nikto|nessus|acunetix|nmap|masscan|wpscan|dirbuster|gobuster|\bffuf\b|wfuzz|havij|netsparker|burpcollaborator|zgrab|nuclei|openvas|w3af|arachni|metasploit|\bhydra\b|jaeles|feroxbuster|commix|xsser|skipfish|whatweb|appscan|webinspect|zaproxy|owasp zap|bsqlbf|pangolin`},
	{"ZW-913110", gScanner, 2, scoreError, "Probe for a common sensitive path", tPath,
		[]string{"/.env", "/.git/", "/.svn/", "/.hg/", "wp-login", "wp-admin", "xmlrpc.php", "phpmyadmin", "/.aws/", ".ds_store", "server-status",
			"/actuator/", "cgi-bin/", ".htaccess", "phpinfo", "vendor/phpunit", "solr/admin", "manager/html", "jmx-console"},
		`/(?:\.env|\.git/|\.svn/|\.hg/|wp-login\.php|wp-admin/|xmlrpc\.php|phpmyadmin|\.aws/|\.ds_store|server-status|actuator/(?:env|heapdump|threaddump|mappings|beans)|cgi-bin/|\.htaccess|phpinfo|vendor/phpunit|solr/admin|manager/html|jmx-console)`},

	// ---- protocol checks, implemented in code ----
	{"ZW-920100", gProtocol, 1, scoreCritical, "Unknown request method", 0, nil, ""},
	{"ZW-920110", gProtocol, 1, scoreError, "TRACE or TRACK request", 0, nil, ""},
	{"ZW-920120", gProtocol, 2, scoreWarning, "Unusually many request headers", 0, nil, ""},
	{"ZW-920130", gProtocol, 1, scoreError, "Request URI longer than 8 KB", 0, nil, ""},
	{"ZW-920170", gProtocol, 1, scoreError, "NUL byte in the request", 0, nil, ""},
	{"ZW-920190", gProtocol, 1, scoreError, "Range header with many ranges", 0, nil, ""},
	{"ZW-920200", gProtocol, 1, scoreCritical, "Proxy request header (httpoxy)", 0, nil, ""},
}
