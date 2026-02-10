module.exports = {
  apps: [
    {
      name: "triproxy-agent",
      script: "python",
      args: "-m agent.watchdog config/agent.yaml",
      cwd: ".",
      interpreter: "none",
    },
    {
      name: "triproxy-relay",
      script: "python",
      args: "-m relay.watchdog config/relay.yaml",
      cwd: ".",
      interpreter: "none",
    },
    {
      name: "triproxy-client",
      script: "python",
      args: "-m client.watchdog config/client.yaml",
      cwd: ".",
      interpreter: "none",
    },
  ],
};

