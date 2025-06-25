import requests

r = requests.get("http://husky.9pw7rf479w.workers.dev")
#r = requests.get("http://minesweeper-revamped.pages.dev")
print(r.content.decode())