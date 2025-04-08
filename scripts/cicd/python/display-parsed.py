import json

from argparse import ArgumentParser, Namespace

from typing import Iterable

def parse_args() -> Namespace:
    parser = ArgumentParser(description="Parse Robot Framework output XML file.")
    parser.add_argument(
        "--traffic-light-file",
        help="Path to the traffic lights json file.",
    )
    return parser.parse_args()

class _TrafficLightDisplayer(object):

    _EMOJI_MAP = {
        "red": "🛑",
        "yellow": "🟡",
        "orange": "🟠",
        "grey": "⚪",
        "blue": "🔵",
        "green": "🟢",
    }

    def __init__(self, traffic_light_file: str):
        self._traffic_light_file = traffic_light_file
        with open(traffic_light_file, "r") as f:
            data = json.load(f)
        self._data = data

    def _display(self, key: str, traffic_light :str) -> str:
        return f'{key}: {self._EMOJI_MAP[traffic_light]}'
    
    def _simple_assemble(self) -> Iterable[str]:
        result = []
        for key, value in self._data.get('tags', {}).items():
            result.append(f'Tag: {self._display(key, value)}')
        result.append(f'Total: {self._display("total", self._data.get("total"))}')
        return result
    
    def render(self) -> None:
        result = self._simple_assemble()
        print(f'Traffic Light Summary for file: {self._traffic_light_file}')
        print("    ")
        print("\n    ".join(result))
        print("")


def main() -> None:
    args = parse_args()
    displayer = _TrafficLightDisplayer(args.traffic_light_file)
    displayer.render()

if __name__ == "__main__":
    main()
        

