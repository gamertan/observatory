// SPDX-License-Identifier: AGPL-3.0-only

package site

type HeadView struct {
	Title        string
	Description  string
	CanonicalURL string
	Assets       Assets
}

type LandingView struct{ Head HeadView }

type LoginView struct {
	Head         HeadView
	CSRFToken    string
	ErrorMessage string
}

type PasswordView struct {
	Head         HeadView
	CSRFToken    string
	ErrorMessage string
}

type OrganizationOption struct {
	ID       string
	Name     string
	Selected bool
}

type TableColumn struct {
	Label string
	Unit  string
}

type TableRow struct{ Values []string }

type TableView struct {
	Caption string
	Columns []TableColumn
	Rows    []TableRow
	Empty   string
}

type SignalView struct {
	ID          string
	Name        string
	Description string
	Query       string
	Table       TableView
}

type SavedQuerySummary struct {
	ID          string
	Name        string
	Description string
	Query       string
}

type DashboardSummary struct {
	Slug        string
	Name        string
	Description string
	PanelCount  int
}

type AppView struct {
	Head           HeadView
	DisplayName    string
	Organizations  []OrganizationOption
	Organization   OrganizationOption
	Signals        []SignalView
	SavedQueries   []SavedQuerySummary
	Dashboards     []DashboardSummary
	CSRFToken      string
	ManageCSRF     string
	CanManage      bool
	EventsURL      string
	RefreshedAt    string
	ProjectionLag  string
	PendingBatches int
	IncidentsURL   string
	OpenIncidents  int
}

type QueryStatsView struct {
	ScannedRows  int
	MatchedRows  int
	ScannedBytes string
	Duration     string
	Truncated    bool
	Approximate  bool
}

type ExploreView struct {
	Head         HeadView
	DisplayName  string
	Organization OrganizationOption
	Query        string
	CSRFToken    string
	EventsURL    string
	Executed     bool
	ErrorMessage string
	Table        TableView
	Stats        QueryStatsView
}

type IncidentSummary struct {
	ID            string
	Title         string
	State         string
	Severity      string
	StartedAt     string
	UpdatedAt     string
	SilencedUntil string
}

type AlertRuleSummary struct {
	Name            string
	Description     string
	Severity        string
	Enabled         bool
	Interval        string
	LastEvaluatedAt string
	LastError       string
}

type IncidentInboxView struct {
	Head          HeadView
	DisplayName   string
	Organization  OrganizationOption
	Incidents     []IncidentSummary
	Rules         []AlertRuleSummary
	SavedQueries  []SavedQuerySummary
	CanManage     bool
	ManageCSRF    string
	EventsURL     string
	OfflineURL    string
	CacheKey      string
	OpenCount     int
	PushPublicKey string
	PushCSRF      string
}

type OfflineIncidentView struct {
	Head         HeadView
	Organization OrganizationOption
	Incidents    []IncidentSummary
	CapturedAt   string
}

type OfflineView struct{ Head HeadView }

type PanelView struct {
	ID            string
	SavedQueryID  string
	Title         string
	Visualization string
	Query         string
	Stat          string
	Chart         ChartView
	Table         TableView
}

type ChartPoint struct {
	Label   string
	Value   string
	Maximum string
	Display string
}

type ChartView struct {
	Label  string
	Points []ChartPoint
}

type DashboardView struct {
	Head         HeadView
	DisplayName  string
	Organization OrganizationOption
	ID           string
	Slug         string
	Revision     int
	Name         string
	Description  string
	ExportURL    string
	Panels       []PanelView
	SavedQueries []SavedQuerySummary
	CanManage    bool
	ManageCSRF   string
}
