function timeTracking() {
  return {
    selectedUser: "",
    selectedDate: new Date().toISOString().slice(0, 10),
    sessions: [],
    status: "abwesend",
    init() {
      this.loadSessions();
    },
    async request(path, payload) {
      const response = await fetch(path, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams(payload),
      });
      return response.json();
    },
    async loadStatus() {
      if (!this.selectedUser) return;
      const response = await fetch(`/status/${this.selectedUser}`);
      const data = await response.json();
      this.status = data.status;
    },
    async startSession() {
      if (!this.selectedUser) return;
      await this.request("/start", { user_id: this.selectedUser });
      await this.loadSessions();
      await this.loadStatus();
    },
    async stopSession() {
      if (!this.selectedUser) return;
      await this.request("/stop", { user_id: this.selectedUser });
      await this.loadSessions();
      await this.loadStatus();
    },
    async loadSessions() {
      const params = new URLSearchParams();
      if (this.selectedUser) params.append("user_id", this.selectedUser);
      if (this.selectedDate) params.append("date", this.selectedDate);
      const response = await fetch(`/sessions?${params.toString()}`);
      const data = await response.json();
      this.sessions = data.sessions || [];
    },
    async saveNote(session) {
      await this.request("/note", { session_id: session.id, note: session.note || "" });
      await this.loadSessions();
    },
    formatDate(value) {
      const date = new Date(value);
      return date.toLocaleString("de-DE", {
        dateStyle: "short",
        timeStyle: "short",
      });
    },
  };
}
