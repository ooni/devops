### Quickstart

It's recommended to make use of a virtualenv, for example managed using `pyenv virtualenv`:
```
pyenv virtualenv ooni-devops
pyenv activate ooni-devops
```

Install deps:
```
pip install ansible dnspython boto3
```

Run playbook:
```
ansible-playbook playbook.yml -i inventory
```
