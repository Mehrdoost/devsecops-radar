from flask import Flask, jsonify, request
from devsecops_radar.web.dashboard.routes import dashboard_bp
from devsecops_radar.web.attack_paths.routes import attack_paths_bp
from devsecops_radar.web.topology.routes import topology_bp
from devsecops_radar.web.summary.routes import summary_bp
from devsecops_radar.web.sentry.routes import sentry_bp
from devsecops_radar.core.auth import login_required, create_token
from devsecops_radar.core.settings import settings

def create_app():
    app = Flask(__name__)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(attack_paths_bp)
    app.register_blueprint(topology_bp)
    app.register_blueprint(summary_bp)
    app.register_blueprint(sentry_bp)

    @app.route('/api/auth/login', methods=['POST'])
    def login():
        data = request.get_json() or {}
        if data.get("password") == settings.PIPELINE_API_KEY:
            token = create_token()
            return jsonify({"token": token})
        return jsonify({"error": "Invalid credentials"}), 403

    return app

def start_server():
    app = create_app()
    app.run(host=settings.HOST, port=settings.PORT, debug=settings.DEBUG)

if __name__ == '__main__':
    start_server()