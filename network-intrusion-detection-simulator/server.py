from flask import Flask, render_template
from flask_socketio import SocketIO, emit

from models import (
    init_db,
    clear_alerts,
    get_last_alerts,
    update_device,
    log_alert,
    get_devices
)

app = Flask(__name__)
app.config["SECRET_KEY"] = "cybersecurity-demo"

socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# Initialize database on startup
init_db()
clear_alerts()


@app.route("/")
def index():
    return render_template("index.html")


@socketio.on("connect")
def handle_connect():
    print("[Web] Client connected")

    # Send initial data to dashboard
    emit("load_alerts", get_last_alerts(20))
    emit("devices_list", get_devices())


@socketio.on("request_devices")
def handle_device_request():
    """
    Sends updated device list when frontend requests it
    """
    emit("devices_list", get_devices())


def receive_new_alert(src_ip, alert_type, detail):
    """
    Central event handler for all simulated IDS alerts
    """

    # Store alert in database
    log_alert(src_ip, alert_type, detail)

    # Update device last seen time
    update_device(src_ip)

    # Broadcast to all connected clients
    socketio.emit("display_alert", {
        "src_ip": src_ip,
        "type": alert_type,
        "detail": detail
    })


if __name__ == "__main__":
    print("[System] Starting Cyber Security Dashboard...")
    socketio.run(app, host="0.0.0.0", port=5000)
