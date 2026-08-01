Before running the server and client, set the same environment variable in both terminals:

```bash
export THERMOMETER_PASSWORD='ChooseAStrongLabPassword'
```

---

## Usage

**Note: I have updated the requirements.txt to be python 3.12 compatible**

```
$ cd lab3
$ python3 -m venv .venv
$ source .venv/bin/activate
$ pip3 install -r requirements.txt
$ python3 SampleNetworkServer.py
```

Open a new terminal instance and run

```
$ cd lab3
$ export FLASK_APP="app.py"
$ flask run
```