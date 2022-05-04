You can do cherry picking and rebasing without locally checking out those branches.
It uses Github low level API to do the work.
It is single script tool with zero dependency.


### Cherry pick commit onto target branch

```
python main.py --token <github_token> --targetbranch <branchname> commit_sha
```

### Rebase branch onto target branch
```
python main.py --token <github_token> --action rebase --targetbranch <to_branch_name> <from_branch_name>
```

###Caveats:
It may fail if there is conflicts.