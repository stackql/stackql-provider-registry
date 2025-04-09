

# per https://docs.robotframework.org/docs/parsing_results

from robot.api import ExecutionResult
import sys
import json

from argparse import ArgumentParser, Namespace


def parse_args() -> Namespace:
    parser = ArgumentParser(description="Parse Robot Framework output XML file.")
    parser.add_argument(
        "--robot-output-file",
        help="Path to the Robot Framework output XML file to parse.",
    )
    return parser.parse_args()




class _CustomSummary(object):

    def __init__(self, result_file_path: str):
        self._result_file_path: str = result_file_path
        self._result = ExecutionResult(self._result_file_path)

    @property
    def statistics(self):
        return self._result.statistics

class _CustomAnalyzer(object):

    def __init__(self, summary: _CustomSummary):
        self._summary: _CustomSummary = summary


    def get_statistics(self) -> dict:
        stats = self._summary.statistics
        tag_dict = {}
        for k, v in stats.tags.tags.items():
            tag_dict[k] = {
                "failed": v.failed,
                "passed": v.passed,
                "skipped": v.skipped,
                "elapsed": v.elapsed,
            }
        summary_dict = {
            "failed": stats.total.failed,
            "passed": stats.total.passed,
            "skipped": stats.total.skipped,
            "total": stats.total.total,
            "message": stats.total.message,
            "tags_expanded": tag_dict,
            # "suite": suite_dict,
        }
        return summary_dict


class _DefaultTrafficLightAnalytics(object):

    def __init__(self, analyzer: _CustomAnalyzer):
        self._analyzer: _CustomAnalyzer = analyzer

    def _get_traffic_light(self, v: dict) -> str:
        total = v["passed"] + v["failed"]
        if total == 0:
            return "grey"
        fail_ratio = v["failed"] / total if total > 0 else 0
        if fail_ratio == 0:
            return "green"
        elif v["failed"] > 0 and v["passed"] == 0:
            return "red"
        elif fail_ratio < 0.3:
            return "yellow"
        elif fail_ratio < 0.7:
            return "orange"
        return "red"

    def get_result_traffic_lights(self) -> dict:
        rv = {}
        tags_dict = {}
        stats = self._analyzer.get_statistics()
        for k, v in stats.get("tags_expanded", {}).items():
            tags_dict[k] = self._get_traffic_light(v)
        rv['tags'] = tags_dict
        rv['total'] = self._get_traffic_light(stats)
        return rv




def main():
    args = parse_args()
    summary = _CustomSummary(args.robot_output_file)
    analyzer = _CustomAnalyzer(summary)
    traffic_lights = _DefaultTrafficLightAnalytics(analyzer)
    traffic_lights = traffic_lights.get_result_traffic_lights()
    print(f"{json.dumps(traffic_lights, sort_keys=True, indent=2)}")
    # analysis_dict = analyzer.get_statistics()
    # print(f"{json.dumps(analysis_dict, sort_keys=True, indent=2)}")

    

if __name__ == "__main__":
    main()

# summary = _CustomSummary('output.xml')
# stats = summary.statistics
# print(f"Number of Failed Tests: {stats.total.failed}")
# print(f"Total number of Tests: {stats.total.passed}")