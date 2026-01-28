function timeTracking() {
  const now = new Date();
  const localDate = new Date(now.getTime() - now.getTimezoneOffset() * 60000)
    .toISOString()
    .slice(0, 10);
  const localMonth = localDate.slice(0, 7);
  return {
    selectedDate: localDate,
    todayDate: localDate,
    payrollMonth: localMonth,
    sessions: [],
    todaySessions: [],
    activeSession: null,
    status: "abwesend",
    nowMs: Date.now(),
    init() {
      this.loadSessions();
      this.loadTodaySessions();
      this.loadStatus();
      setInterval(() => {
        this.nowMs = Date.now();
      }, 1000);
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
      await this.loadTodaySessions();
      await this.loadStatus();
    },
    async stopSession() {
      await this.request("/stop", {});
      await this.loadSessions();
      await this.loadTodaySessions();
      await this.loadStatus();
    },
    async loadSessions() {
      const params = new URLSearchParams();
      if (this.selectedDate) params.append("date", this.selectedDate);
      const offsetDate = this.selectedDate
        ? new Date(`${this.selectedDate}T00:00:00`)
        : new Date();
      params.append("tz_offset", offsetDate.getTimezoneOffset());
      const response = await fetch(`/sessions?${params.toString()}`);
      const data = await response.json();
      this.sessions = data.sessions || [];
    },
    async loadTodaySessions() {
      const params = new URLSearchParams();
      params.append("date", this.todayDate);
      const offsetDate = new Date(`${this.todayDate}T00:00:00`);
      params.append("tz_offset", offsetDate.getTimezoneOffset());
      const response = await fetch(`/sessions?${params.toString()}`);
      const data = await response.json();
      this.todaySessions = data.sessions || [];
      this.activeSession = this.todaySessions.find((session) => !session.end_time) || null;
    },
    async saveNote(session) {
      await this.request("/note", { session_id: session.id, note: session.note || "" });
      await this.loadSessions();
      await this.loadTodaySessions();
    },
    async saveActiveNote() {
      if (!this.activeSession) return;
      await this.request("/note", {
        session_id: this.activeSession.id,
        note: this.activeSession.note || "",
      });
      await this.loadTodaySessions();
    },
    todayTotalLabel() {
      const totalSeconds = this.calculateTotalSeconds(this.todaySessions, true);
      return this.formatDuration(totalSeconds);
    },
    calculateTotalSeconds(sessions, includeActive) {
      let total = 0;
      sessions.forEach((session) => {
        const start = new Date(session.start_time).getTime();
        let end = session.end_time ? new Date(session.end_time).getTime() : null;
        if (!end && includeActive) {
          end = this.nowMs;
        }
        if (!end || end < start) return;
        total += Math.floor((end - start) / 1000);
      });
      return total;
    },
    formatDuration(seconds) {
      const hours = Math.floor(seconds / 3600);
      const minutes = Math.floor((seconds % 3600) / 60);
      return `${hours}h ${String(minutes).padStart(2, "0")}m`;
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
