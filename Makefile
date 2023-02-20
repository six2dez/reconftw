GH_CLI := $(shell command -v gh 2> /dev/null)
PRIVATE_REPO := $(shell echo $${PRIV_REPO-reconftw-data})

.PHONY: sync upload bootstrap rm

# bootstrap a private repo to store data
bootstrap:
	@if [ -z $(GH_CLI) ]; then echo "github cli is missing. please install"; exit 2; fi
	gh repo create $(PRIVATE_REPO) --private
	gh repo clone $(PRIVATE_REPO) ~/$(PRIVATE_REPO)
	cd ~/$(PRIVATE_REPO) && git commit --allow-empty -m "Empty commit" && \
		git remote add upstream https://github.com/six2dez/reconftw && \
		git fetch upstream && \
		git rebase upstream/main $(shell git symbolic-ref refs/remotes/origin/HEAD | sed 's@^refs/remotes/origin/@@') && \
		mkdir Recon && \
		git push origin $(shell git symbolic-ref refs/remotes/origin/HEAD | sed 's@^refs/remotes/origin/@@')
	@echo "Done!"
	@echo "Initialized private repo: $(PRIVATE_REPO)"

rm:
	gh repo delete $(PRIVATE_REPO) --yes
	rm -rf ~/$(PRIVATE_REPO)

sync:
	cd ~/$(PRIVATE_REPO) && git fetch upstream && git rebase upstream/main $(shell git symbolic-ref refs/remotes/origin/HEAD | sed 's@^refs/remotes/origin/@@')

upload:
	cd ~/$(PRIVATE_REPO) && \
		git add . && \
		git commit -m "Data upload" && \
		git push origin $(shell git symbolic-ref refs/remotes/origin/HEAD | sed 's@^refs/remotes/origin/@@')
