package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var windows bool
var selectedDeviceIndex int

// Packet data message
type packetMsg struct {
	number    int
	timestamp string
	srcIP     string
	dstIP     string
	protocol  string
	srcPort   string
	dstPort   string
	size      string
	payload   string
}

// Styles for the interface selection
var (
	titleStyle        = lipgloss.NewStyle().MarginLeft(2)
	itemStyle         = lipgloss.NewStyle().PaddingLeft(4)
	selectedItemStyle = lipgloss.NewStyle().PaddingLeft(2).Foreground(lipgloss.Color("170"))
	paginationStyle   = list.DefaultStyles().PaginationStyle.PaddingLeft(4)
	helpStyle         = list.DefaultStyles().HelpStyle.PaddingLeft(4).PaddingBottom(1)
	quitTextStyle     = lipgloss.NewStyle().Margin(1, 0, 2, 4)
)

// Styles for the packet table
var baseStyle = lipgloss.NewStyle().
	BorderStyle(lipgloss.NormalBorder()).
	BorderForeground(lipgloss.Color("240"))

// List item for interface selection
type item string

func (i item) FilterValue() string { return "" }

type itemDelegate struct{}

func (d itemDelegate) Height() int                             { return 1 }
func (d itemDelegate) Spacing() int                            { return 0 }
func (d itemDelegate) Update(_ tea.Msg, _ *list.Model) tea.Cmd { return nil }
func (d itemDelegate) Render(w io.Writer, m list.Model, index int, listItem list.Item) {
	i, ok := listItem.(item)
	if !ok {
		return
	}

	str := fmt.Sprintf("%d. %s", index+1, i)

	fn := itemStyle.Render
	if index == m.Index() {
		fn = func(s ...string) string {
			return selectedItemStyle.Render("> " + strings.Join(s, " "))
		}
	}

	fmt.Fprint(w, fn(str))
}

// Interface selection model
type interfaceModel struct {
	list     list.Model
	choice   string
	quitting bool
	index    int
	width    int
	height   int
}

func (m interfaceModel) Init() tea.Cmd {
	return nil
}

func (m interfaceModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

		// Update list dimensions
		m.list.SetWidth(msg.Width)
		m.list.SetHeight(msg.Height - 4) // Leave some space for margins
		return m, nil

	case tea.KeyMsg:
		switch keypress := msg.String(); keypress {
		case "q", "ctrl+c":
			m.quitting = true
			return m, tea.Quit

		case "enter":
			i, ok := m.list.SelectedItem().(item)
			if ok {
				m.choice = string(i)
				selectedDeviceIndex = m.list.Index()
				m.index = selectedDeviceIndex
			}
			return m, tea.Quit
		}
	}

	var cmd tea.Cmd
	m.list, cmd = m.list.Update(msg)
	return m, cmd
}

func (m interfaceModel) View() string {
	if m.choice != "" {
		return quitTextStyle.Render(fmt.Sprintf("%s Selected", m.choice))
	}
	if m.quitting {
		return quitTextStyle.Render("Exiting...")
	}
	return "\n" + m.list.View()
}

// Packet capture table model
type packetTableModel struct {
	table       table.Model
	packets     chan packetMsg
	quitting    bool
	packetCount int
	seenPackets map[string]bool
	width       int
	height      int
}

func (m packetTableModel) Init() tea.Cmd {
	return waitForPacket(m.packets)
}

func (m packetTableModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

		// Recalculate column widths based on new window size
		m.table = m.updateTableDimensions(m.table, msg.Width, msg.Height)
		return m, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			m.quitting = true
			return m, tea.Quit
		case "enter":
			selected := m.table.SelectedRow()
			if len(selected) > 1 {
				return m, tea.Printf("Selected packet: %s -> %s", selected[1], selected[2])
			}
		}
		// Update the table with key events for navigation
		m.table, cmd = m.table.Update(msg)
		return m, cmd

	case packetMsg:
		// Create a unique key for this packet to check for duplicates
		packetKey := fmt.Sprintf("%s-%s-%s-%s-%s-%s",
			msg.srcIP, msg.dstIP, msg.protocol, msg.srcPort, msg.dstPort, msg.size)

		// Skip if we've already seen this exact packet
		if m.seenPackets[packetKey] {
			return m, waitForPacket(m.packets)
		}

		// Mark this packet as seen
		m.seenPackets[packetKey] = true

		// Increment packet counter
		m.packetCount++

		// Get current data column width for payload truncation
		dataColWidth := 35 // default
		if len(m.table.Columns()) > 8 {
			dataColWidth = m.table.Columns()[8].Width
		}

		// Adjust payload length based on current column width
		adjustedPayload := asciiPrintable([]byte(msg.payload), dataColWidth)

		// Handle different column layouts based on window size
		var newRow table.Row
		if len(m.table.Columns()) == 5 {
			// Very small window layout
			newRow = table.Row{
				fmt.Sprintf("%d", m.packetCount),
				msg.srcIP,
				msg.dstIP,
				msg.protocol,
				adjustedPayload,
			}
		} else {
			// Normal layout
			newRow = table.Row{
				fmt.Sprintf("%d", m.packetCount),
				msg.timestamp,
				msg.srcIP,
				msg.dstIP,
				msg.protocol,
				msg.srcPort,
				msg.dstPort,
				msg.size,
				adjustedPayload,
			}
		}

		// Add the new packet to the table
		rows := m.table.Rows()
		rows = append(rows, newRow)
		m.table.SetRows(rows)

		// Continue listening for packets
		return m, waitForPacket(m.packets)
	}

	// For any other messages, just update the table
	m.table, cmd = m.table.Update(msg)
	return m, cmd
}

func (m packetTableModel) updateTableDimensions(t table.Model, width, height int) table.Model {
	// Calculate available width (subtract some for borders and padding)
	availableWidth := width - 4

	// Calculate table height (subtract space for help text and borders)
	tableHeight := height - 6
	if tableHeight < 5 {
		tableHeight = 5
	}

	// Define minimum and preferred column widths
	minWidths := map[string]int{
		"#":         4,
		"Time":      8,
		"Source IP": 12,
		"Dest IP":   12,
		"Protocol":  8,
		"Src Port":  8,
		"Dst Port":  8,
		"Size":      6,
		"Data":      15,
	}

	preferredWidths := map[string]int{
		"#":         6,
		"Time":      10,
		"Source IP": 18,
		"Dest IP":   18,
		"Protocol":  10,
		"Src Port":  10,
		"Dst Port":  10,
		"Size":      8,
		"Data":      40,
	}

	// Calculate total minimum width required
	totalMinWidth := 0
	for _, w := range minWidths {
		totalMinWidth += w
	}

	// Calculate new column widths
	var columns []table.Column

	if availableWidth <= totalMinWidth {
		// Window is too small, hide some columns and prioritize essential ones
		if availableWidth < 40 {
			// Very small window - show only essential columns
			columns = []table.Column{
				{Title: "#", Width: 4},
				{Title: "Src", Width: 12},
				{Title: "Dst", Width: 12},
				{Title: "Proto", Width: 6},
				{Title: "Data", Width: max(8, availableWidth-34)},
			}
		} else {
			// Small window - use minimum widths
			columns = []table.Column{
				{Title: "#", Width: minWidths["#"]},
				{Title: "Time", Width: minWidths["Time"]},
				{Title: "Source IP", Width: minWidths["Source IP"]},
				{Title: "Dest IP", Width: minWidths["Dest IP"]},
				{Title: "Protocol", Width: minWidths["Protocol"]},
				{Title: "Src Port", Width: minWidths["Src Port"]},
				{Title: "Dst Port", Width: minWidths["Dst Port"]},
				{Title: "Size", Width: minWidths["Size"]},
				{Title: "Data", Width: minWidths["Data"]},
			}
		}
	} else {
		// First, try to use preferred widths
		totalPreferredWidth := 0
		for _, w := range preferredWidths {
			totalPreferredWidth += w
		}

		if availableWidth >= totalPreferredWidth {
			// We have enough space for preferred widths, give extra to data column
			dataWidth := preferredWidths["Data"] + (availableWidth - totalPreferredWidth)
			columns = []table.Column{
				{Title: "#", Width: preferredWidths["#"]},
				{Title: "Time", Width: preferredWidths["Time"]},
				{Title: "Source IP", Width: preferredWidths["Source IP"]},
				{Title: "Dest IP", Width: preferredWidths["Dest IP"]},
				{Title: "Protocol", Width: preferredWidths["Protocol"]},
				{Title: "Src Port", Width: preferredWidths["Src Port"]},
				{Title: "Dst Port", Width: preferredWidths["Dst Port"]},
				{Title: "Size", Width: preferredWidths["Size"]},
				{Title: "Data", Width: dataWidth},
			}
		} else {
			// Scale between minimum and preferred widths
			scaleFactor := float64(availableWidth) / float64(totalPreferredWidth)

			columns = []table.Column{
				{Title: "#", Width: max(minWidths["#"], int(float64(preferredWidths["#"])*scaleFactor))},
				{Title: "Time", Width: max(minWidths["Time"], int(float64(preferredWidths["Time"])*scaleFactor))},
				{Title: "Source IP", Width: max(minWidths["Source IP"], int(float64(preferredWidths["Source IP"])*scaleFactor))},
				{Title: "Dest IP", Width: max(minWidths["Dest IP"], int(float64(preferredWidths["Dest IP"])*scaleFactor))},
				{Title: "Protocol", Width: max(minWidths["Protocol"], int(float64(preferredWidths["Protocol"])*scaleFactor))},
				{Title: "Src Port", Width: max(minWidths["Src Port"], int(float64(preferredWidths["Src Port"])*scaleFactor))},
				{Title: "Dst Port", Width: max(minWidths["Dst Port"], int(float64(preferredWidths["Dst Port"])*scaleFactor))},
				{Title: "Size", Width: max(minWidths["Size"], int(float64(preferredWidths["Size"])*scaleFactor))},
				{Title: "Data", Width: max(minWidths["Data"], int(float64(preferredWidths["Data"])*scaleFactor))},
			}
		}
	}

	// Create new table with updated dimensions
	newTable := table.New(
		table.WithColumns(columns),
		table.WithHeight(tableHeight),
		table.WithFocused(true),
		table.WithStyles(table.DefaultStyles()),
	)

	// Copy existing rows to new table
	newTable.SetRows(t.Rows())

	// Copy cursor position
	newTable.SetCursor(t.Cursor())

	return newTable
}

func (m packetTableModel) View() string {
	if m.quitting {
		return quitTextStyle.Render("Stopping packet capture...")
	}

	// Adjust help text based on window width
	helpText := "\nPress ↑/↓ to navigate, Enter to select, q to quit\n"
	if m.width < 60 {
		helpText = "\n↑/↓ nav, Enter select, q quit\n"
	}

	return baseStyle.Render(m.table.View()) + helpText
}

// Helper function for max (Go 1.18+ has this built-in)
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// Wait for packet from channel
func waitForPacket(packets chan packetMsg) tea.Cmd {
	return func() tea.Msg {
		return <-packets
	}
}

// Utility functions
func asciiPrintable(data []byte, maxLen int) string {
	if maxLen < 3 {
		maxLen = 3 // Minimum to show "..."
	}

	printable := make([]byte, 0, len(data))
	for _, b := range data {
		if b >= 32 && b <= 126 {
			printable = append(printable, b)
		}
	}
	result := string(printable)
	// Truncate if too long for display
	if len(result) > maxLen {
		result = result[:maxLen-3] + "..."
	}
	return result
}

func extractPacketInfo(packet gopacket.Packet) packetMsg {
	pkt := packetMsg{
		number:    0, // Will be set by the table model
		timestamp: time.Now().Format("15:04:05"),
		srcIP:     "",
		dstIP:     "",
		protocol:  "",
		srcPort:   "",
		dstPort:   "",
		size:      fmt.Sprintf("%d", len(packet.Data())),
		payload:   asciiPrintable(packet.Data(), 35), // Default length, will be adjusted
	}

	// Extract IP information
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		pkt.srcIP = ip.SrcIP.String()
		pkt.dstIP = ip.DstIP.String()
		pkt.protocol = ip.Protocol.String()
	}

	// Extract TCP information
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		pkt.srcPort = fmt.Sprintf("%d", tcp.SrcPort)
		pkt.dstPort = fmt.Sprintf("%d", tcp.DstPort)
		pkt.protocol = "TCP"
	}

	// Extract UDP information
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		pkt.srcPort = fmt.Sprintf("%d", udp.SrcPort)
		pkt.dstPort = fmt.Sprintf("%d", udp.DstPort)
		pkt.protocol = "UDP"
	}

	return pkt
}

func selectInterface() (string, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return "", err
	}

	var items []list.Item
	var deviceNames []string

	for _, device := range devices {
		for _, address := range device.Addresses {
			if address.IP.To4() != nil && !address.IP.IsLoopback() {
				deviceNames = append(deviceNames, device.Name)
				if windows {
					items = append(items, item(device.Description))
				} else {
					items = append(items, item(device.Name))
				}
				break
			}
		}
	}

	if len(items) == 0 {
		return "", fmt.Errorf("no suitable network interfaces found")
	}

	// Create list with dynamic sizing
	l := list.New(items, itemDelegate{}, 50, 20) // Initial dimensions, will be updated
	l.Title = "Select network interface to monitor"
	l.SetShowStatusBar(false)
	l.SetFilteringEnabled(false)
	l.Styles.Title = titleStyle
	l.Styles.PaginationStyle = paginationStyle
	l.Styles.HelpStyle = helpStyle

	m := interfaceModel{list: l}

	if _, err := tea.NewProgram(m, tea.WithAltScreen()).Run(); err != nil {
		return "", err
	}

	if selectedDeviceIndex >= len(deviceNames) {
		return "", fmt.Errorf("invalid device selection")
	}

	return deviceNames[selectedDeviceIndex], nil
}

func capturePackets(deviceName string, packets chan packetMsg) {
	handle, err := pcap.OpenLive(deviceName, 65535, false, -1*time.Second)
	if err != nil {
		log.Printf("Error opening device: %v", err)
		return
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		pkt := extractPacketInfo(packet)
		select {
		case packets <- pkt:
		default:
			// Channel is full, skip this packet
		}
	}
}

func main() {
	if runtime.GOOS == "windows" {
		windows = true
	}

	args := os.Args
	if len(args) != 1 {
		fmt.Println("File mode not implemented in this version")
		return
	}

	// Select network interface
	deviceName, err := selectInterface()
	if err != nil {
		log.Fatal("Error selecting interface:", err)
	}

	// Create packet channel
	packets := make(chan packetMsg, 100)

	// Start packet capture in background
	go capturePackets(deviceName, packets)

	// Create initial table with default dimensions (will be updated on first WindowSizeMsg)
	columns := []table.Column{
		{Title: "#", Width: 6},
		{Title: "Time", Width: 10},
		{Title: "Source IP", Width: 18},
		{Title: "Dest IP", Width: 18},
		{Title: "Protocol", Width: 10},
		{Title: "Src Port", Width: 10},
		{Title: "Dst Port", Width: 10},
		{Title: "Size", Width: 8},
		{Title: "Data", Width: 40},
	}

	// Create table
	t := table.New(
		table.WithColumns(columns),
		table.WithHeight(30),
		table.WithFocused(true),
		table.WithStyles(table.DefaultStyles()),
	)

	// Initialize with empty rows
	t.SetRows([]table.Row{})

	// Create model
	m := packetTableModel{
		table:       t,
		packets:     packets,
		seenPackets: make(map[string]bool),
	}

	// Run the program
	if err := tea.NewProgram(m, tea.WithAltScreen()).Start(); err != nil {
		fmt.Println("Error running program:", err)
		os.Exit(1)
	}
}
