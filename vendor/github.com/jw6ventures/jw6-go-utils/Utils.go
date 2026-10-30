package jw6_utils

import (
	"fmt"
	"strings"
	"time"
)

// ANSI color codes
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
)

type Utils struct {
	LogLevel LogLevel
}

type LogLevel int

const (
	Trace LogLevel = iota
	Debug
	Info
	Warn
	Error
	Fatal
)

func LogLevelFromString(level string) LogLevel {
	switch level {
	case "Trace":
		return Trace
	case "Debug":
		return Debug
	case "Info":
		return Info
	case "Warn":
		return Warn
	case "Error":
		return Error
	case "Fatal":
		return Fatal
	default:
		fmt.Println("Default log level (Info) applied")
		return Info
	}
}

// Method to get the label of the LogLevel constant
func (l LogLevel) String() string {
	labels := [...]string{"Trace", "Debug", "Info", "Warn", "Error", "Fatal"}
	if l < Trace || l > Fatal {
		return "Unknown"
	}
	return labels[l]
}

func (u *Utils) Log(class string, method string, level LogLevel, message string) {
	if level < u.LogLevel {
		return
	}

	formattedTime := time.Now().Format("2006-01-02 15:04:05")

	// Determine color based on log level
	var color string
	switch level {
	case Debug:
		color = colorBlue
	case Info:
		color = colorGreen
	case Warn:
		color = colorYellow
	case Error, Fatal:
		color = colorRed
	default:
		color = "" // No color for Trace
	}

	// Build the log tags
	logTags := fmt.Sprintf("%s [%s][%s][%s] - ", formattedTime, class, method, level.String())

	if level == Fatal {
		fmt.Println("******************************************************************************************************************")
	}

	if color != "" {
		fmt.Printf("%s%s%s%s\n", logTags, color, message, colorReset)
	} else {
		fmt.Printf("%s%s\n", logTags, message)
	}

	if level == Fatal {
		fmt.Println("******************************************************************************************************************")
	}
}

func (u *Utils) PrintBanner(product string, version string, copyrightYear string, hashes int, copyrightOwner string) {
	versionString := "Version " + version
	copyrightString := "Copyright " + copyrightYear + " " + copyrightOwner
	interior := max(len(product), len(versionString), len(copyrightString)) + 6

	headerHashString := strings.Repeat("#", hashes+interior+hashes)
	hashString := strings.Repeat("#", hashes)

	fmt.Println(headerHashString)
	fmt.Println(hashString + u.centerInString(product, interior) + hashString)
	fmt.Println(hashString + u.centerInString(versionString, interior) + hashString)
	fmt.Println(hashString + u.centerInString(copyrightString, interior) + hashString)
	fmt.Println(headerHashString)
	fmt.Println("")
	fmt.Println("")
}

func (u Utils) centerInString(word string, spaces int) string {
	spacesNeeded := spaces - len(word)
	spacesNeededBefore := spacesNeeded / 2
	spacesNeededAfter := spacesNeeded - spacesNeededBefore

	return strings.Repeat(" ", spacesNeededBefore) + word + strings.Repeat(" ", spacesNeededAfter)
}
