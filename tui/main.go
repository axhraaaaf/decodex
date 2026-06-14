package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

const (
	cyan       = lipgloss.Color("#00FFFF")
	neonGreen  = lipgloss.Color("#39FF14")
	warningYellow = lipgloss.Color("#FFFF00")
	dangerRed  = lipgloss.Color("#FF3131")
	gray       = lipgloss.Color("#808080")
	darkBG     = lipgloss.Color("#121212")
)

var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(cyan).
			Border(lipgloss.DoubleBorder()).
			BorderForeground(cyan).
			Padding(1, 4).
			MarginBottom(1).
			Align(lipgloss.Center)

	headerStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(cyan).
			MarginBottom(1).
			Underline(true)

	selectedItemStyle = lipgloss.NewStyle().
				Foreground(neonGreen).
				Bold(true)

	menuItemStyle = lipgloss.NewStyle().
			PaddingLeft(2)

	resultPanelStyle = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(cyan).
				Padding(1, 2).
				MarginLeft(2)

	footerStyle = lipgloss.NewStyle().
			Foreground(gray).
			MarginTop(1)

	mainLayout = lipgloss.NewStyle().
			Padding(1, 2)

	errorStyle = lipgloss.NewStyle().
			Foreground(dangerRed).
			Bold(true)

	labelStyle = lipgloss.NewStyle().Foreground(gray).Bold(true)
	valueStyle = lipgloss.NewStyle().Foreground(neonGreen)
)

type item string

func (i item) FilterValue() string { return string(i) }

type itemDelegate struct{}

func (d itemDelegate) Height() int                               { return 1 }
func (d itemDelegate) Spacing() int                               { return 0 }
func (d itemDelegate) Update(msg tea.Msg, m *list.Model) tea.Cmd { return nil }
func (d itemDelegate) Render(w io.Writer, m list.Model, index int, listItem list.Item) {
	i, ok := listItem.(item)
	if !ok {
		return
	}

	str := fmt.Sprintf("  %s", i)
	if index == m.Index() {
		str = selectedItemStyle.Render(fmt.Sprintf("▶ %s", i))
	} else {
		str = menuItemStyle.Render(fmt.Sprintf("  %s", i))
	}

	fmt.Fprint(w, str)
}

type model struct {
	list           list.Model
	encodingList   list.Model
	view           string // "menu", "encoding", "input_needed", "results"
	choice         string
	subchoice      string
	input          textinput.Model
	viewport       viewport.Model
	result         string
	isLoading      bool
	err            error
	width          int
	height         int
	lastInput      string
}

func initialModel() model {
	mainItems := []list.Item{
		item("Analyze File"),
		item("Auto Decode"),
		item("Encoding Tools"),
		item("Plugin Manager"),
		item("Risk Reports"),
		item("Exit"),
	}

	l := list.New(mainItems, itemDelegate{}, 30, 10)
	l.Title = "MAIN DASHBOARD"
	l.SetShowStatusBar(false)
	l.SetFilteringEnabled(false)
	l.Styles.Title = headerStyle

	encodingItems := []list.Item{
		item("Base64 Encode"),
		item("Base64 Decode"),
		item("Hex Encode"),
		item("Hex Decode"),
		item("XOR Brute Force"),
		item("Back"),
	}
	el := list.New(encodingItems, itemDelegate{}, 30, 10)
	el.Title = "ENCODING TOOLS"
	el.SetShowStatusBar(false)
	el.SetFilteringEnabled(false)
	el.Styles.Title = headerStyle

	ti := textinput.New()
	ti.Placeholder = "target path or input text..."
	ti.Focus()
	ti.CharLimit = 256
	ti.Width = 40

	vp := viewport.New(60, 20)
	vp.Style = resultPanelStyle

	return model{
		list:         l,
		encodingList: el,
		view:         "menu",
		input:        ti,
		viewport:     vp,
	}
}

func (m model) Init() tea.Cmd {
	return nil
}

type resultMsg struct {
	content string
	err     error
}

func (m model) runCmd() tea.Cmd {
	return func() tea.Msg {
		args := []string{"-m", "decodeX"}

		switch m.choice {
		case "Analyze File":
			args = append(args, "analyze", m.input.Value(), "--json-stdout")
		case "Auto Decode":
			args = append(args, "auto", m.input.Value(), "--json")
		case "Risk Reports":
			args = append(args, "risk", m.input.Value(), "--json")
		case "Plugin Manager":
			args = append(args, "decodeX.plugins", "list")
		case "Encoding Tools":
			switch m.subchoice {
			case "Base64 Encode":
				args = append(args, "base64", "encode", m.input.Value(), "--json")
			case "Base64 Decode":
				args = append(args, "base64", "decode", m.input.Value(), "--json")
			case "Hex Encode":
				args = append(args, "hex", "encode", m.input.Value(), "--json")
			case "Hex Decode":
				args = append(args, "hex", "decode", m.input.Value(), "--json")
			case "XOR Brute Force":
				args = append(args, "xor", "brute", m.input.Value(), "--json")
			}
		}

		cmd := exec.Command("python", args...)
		output, err := cmd.CombinedOutput()
		if err != nil {
			return resultMsg{content: string(output), err: err}
		}
		return resultMsg{content: string(output)}
	}
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.Type {
		case tea.KeyCtrlC:
			return m, tea.Quit
		case tea.KeyEsc, tea.KeyBackspace:
			if m.view == "results" || m.view == "input_needed" {
				if m.view == "input_needed" && m.input.Value() != "" {
					// allow backspace within input
				} else {
					m.view = "menu"
					if m.choice == "Encoding Tools" {
						m.view = "encoding"
					}
					m.input.Reset()
					return m, nil
				}
			} else if m.view == "encoding" {
				m.view = "menu"
				return m, nil
			}
		}

		switch m.view {
		case "menu":
			if msg.Type == tea.KeyEnter {
				i, ok := m.list.SelectedItem().(item)
				if ok {
					m.choice = string(i)
					if m.choice == "Exit" {
						return m, tea.Quit
					}
					if m.choice == "Encoding Tools" {
						m.view = "encoding"
					} else if m.choice == "Plugin Manager" {
						m.isLoading = true
						m.view = "results"
						return m, m.runCmd()
					} else {
						m.view = "input_needed"
						m.input.Focus()
					}
				}
			}
			var cmd tea.Cmd
			m.list, cmd = m.list.Update(msg)
			return m, cmd

		case "encoding":
			if msg.Type == tea.KeyEnter {
				i, ok := m.encodingList.SelectedItem().(item)
				if ok {
					m.subchoice = string(i)
					if m.subchoice == "Back" {
						m.view = "menu"
					} else {
						m.view = "input_needed"
						m.input.Focus()
					}
				}
			}
			var cmd tea.Cmd
			m.encodingList, cmd = m.encodingList.Update(msg)
			return m, cmd

		case "input_needed":
			if msg.Type == tea.KeyEnter {
				if m.input.Value() != "" {
					m.lastInput = m.input.Value()
					m.isLoading = true
					m.view = "results"
					return m, m.runCmd()
				}
			}
			var cmd tea.Cmd
			m.input, cmd = m.input.Update(msg)
			return m, cmd

		case "results":
			var cmd tea.Cmd
			m.viewport, cmd = m.viewport.Update(msg)
			return m, cmd
		}

	case resultMsg:
		m.isLoading = false
		if msg.err != nil {
			m.result = errorStyle.Render(fmt.Sprintf("ERROR DETECTED\n\n%s", msg.content))
		} else {
			m.result = m.formatOutput(msg.content)
		}
		m.viewport.SetContent(m.result)
		return m, nil

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.list.SetHeight(m.height - 15)
		m.encodingList.SetHeight(m.height - 15)
		m.viewport.Width = m.width - 45
		m.viewport.Height = m.height - 18
		return m, nil
	}

	return m, nil
}

func (m model) formatOutput(raw string) string {
	// Attempt to parse JSON
	var data interface{}
	if err := json.Unmarshal([]byte(raw), &data); err != nil {
		return raw // return as is if not JSON
	}

	// Pretty format based on type
	switch v := data.(type) {
	case map[string]interface{}:
		var sb strings.Builder
		if fs, ok := v["file_summary"].(map[string]interface{}); ok {
			sb.WriteString(fmt.Sprintf("%s %v\n", labelStyle.Render("FILE TYPE:"), fs["type_guess"]))
			
			score := 0
			if s, ok := fs["risk_score"].(float64); ok {
				score = int(s)
			}
			
			scoreStyle := neonGreen
			if score > 70 {
				scoreStyle = dangerRed
			} else if score > 30 {
				scoreStyle = warningYellow
			}
			
			sb.WriteString(fmt.Sprintf("%s %s\n", labelStyle.Render("RISK SCORE:"), lipgloss.NewStyle().Foreground(scoreStyle).Render(fmt.Sprintf("%d/100", score))))
			sb.WriteString(fmt.Sprintf("%s %v\n", labelStyle.Render("VERDICT:"), fs["verdict"]))
			sb.WriteString("\n")
		}
		
		// If it's a list (e.g. plugins)
		if plugins, ok := v["decodeX.plugins"].(map[string]interface{}); ok {
			sb.WriteString(headerStyle.Render("PLUGIN FINDINGS") + "\n")
			for k, p := range plugins {
				sb.WriteString(fmt.Sprintf("● %s: %v\n", k, p))
			}
		}

		// General JSON formatting fallback
		pretty, _ := json.MarshalIndent(v, "", "  ")
		if sb.Len() == 0 {
			return string(pretty)
		}
		sb.WriteString("\n--- RAW DATA ---\n")
		sb.WriteString(string(pretty))
		return sb.String()
	default:
		pretty, _ := json.MarshalIndent(v, "", "  ")
		return string(pretty)
	}
}

func (m model) View() string {
	banner := titleStyle.Render("══════════════════════════════\n         decodeX v2\n Professional Cyber Tool TUI\n══════════════════════════════")
	footer := footerStyle.Render("decodeX v2 — Developed by axhraaaaf | UP/DOWN: Move | ENTER: Select | ESC: Back")

	var content string

	switch m.view {
	case "menu":
		content = m.list.View()
	case "encoding":
		content = m.encodingList.View()
	case "input_needed":
		label := m.choice
		if m.choice == "Encoding Tools" {
			label = m.subchoice
		}
		content = lipgloss.JoinVertical(lipgloss.Left,
			headerStyle.Render("ACTION: "+label),
			"\nTarget input required:",
			m.input.View(),
			"\n[ENTER] Execute | [ESC] Cancel",
		)
	case "results":
		leftPanel := ""
		if m.choice == "Encoding Tools" {
			leftPanel = m.encodingList.View()
		} else {
			leftPanel = m.list.View()
		}

		resDisplay := m.viewport.View()
		if m.isLoading {
			resDisplay = resultPanelStyle.Render("\n\n   [ ANALYZING DATA... ]\n   Waiting for backend engine...")
		}

		content = lipgloss.JoinHorizontal(lipgloss.Top,
			lipgloss.NewStyle().Width(35).Render(leftPanel),
			resDisplay,
		)
	}

	return mainLayout.Render(
		lipgloss.JoinVertical(lipgloss.Top,
			banner,
			lipgloss.NewStyle().Height(m.height-12).Render(content),
			footer,
		),
	)
}

func main() {
	p := tea.NewProgram(initialModel(), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Printf("Fatal error: %v", err)
		os.Exit(1)
	}
}
