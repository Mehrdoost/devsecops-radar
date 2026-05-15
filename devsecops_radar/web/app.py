from flask import Flask
from devsecops_radar.web.dashboard.routes import dashboard_bp
from devsecops_radar.web.attack_paths.routes import attack_paths_bp
from devsecops_radar.web.topology.routes import topology_bp
from devsecops_radar.web.summary.routes import summary_bp
from devsecops_radar.web.sentry.routes import sentry_bp

def create_app():
    app = Flask(__name__)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(attack_paths_bp)
    app.register_blueprint(topology_bp)
    app.register_blueprint(summary_bp)
    app.register_blueprint(sentry_bp)
    return app

def start_server(host='0.0.0.0', port=8080):
    app = create_app()
    app.run(host=host, port=port, debug=True)

if __name__ == '__main__':
    start_server()