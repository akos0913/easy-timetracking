function timeTracking() {
  return {
    selectedDate: new Date().toISOString().slice(0, 10),
    sessions: [],
    status: "abwesend",
    init() {
      this.loadSessions();
      this.loadStatus();
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
      const response = await fetch("/status");
      const data = await response.json();
      this.status = data.status;
    },
    async startSession() {
      await this.request("/start", {});
      await this.loadSessions();
      await this.loadStatus();
    },
    async stopSession() {
      await this.request("/stop", {});
      await this.loadSessions();
      await this.loadStatus();
    },
    async loadSessions() {
      const params = new URLSearchParams();
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
