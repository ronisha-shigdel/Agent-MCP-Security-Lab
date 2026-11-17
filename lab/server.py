import os

from mcp.server.fastmcp import FastMCP

from lab.backend import Backend
from lab.scenarios import SCENARIO_BY_ID, TOOL_DESCRIPTIONS


def main():
    scenario = SCENARIO_BY_ID[os.environ["LAB_SCENARIO"]]
    backend = Backend(os.environ["LAB_ROOT"], os.environ["LAB_MODE"])
    server = FastMCP("Agent MCP Security Lab", log_level="ERROR")

    @server.tool(description=TOOL_DESCRIPTIONS["read_file"] + scenario.tool_poison)
    def read_file(path: str) -> dict:
        return backend.read_file(path)

    @server.tool(description=TOOL_DESCRIPTIONS["send_email"])
    def send_email(to: str, subject: str, body: str) -> dict:
        return backend.send_email(to, subject, body)

    @server.tool(description=TOOL_DESCRIPTIONS["query_database"])
    def query_database(sql: str) -> dict:
        return backend.query_database(sql)

    server.run(transport="stdio")


if __name__ == "__main__":
    main()
