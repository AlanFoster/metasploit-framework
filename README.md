# Site

## Running

Running:

```
bundle install
bundle exec jekyll serve --config _config.yml,_config_development.yml --incremental
```

Now visit http://127.0.0.1:4000

### Modifying pages

Firstly modify the markdown content in an editor your choice. Jekyll will rebuild the required file,
and the changes can bee seen after refreshing your browser.

### Adding new pages

Adding additional pages will not regenerate the navigation for all pages.
It is easier to regenerate the entire site again:

```
rm -rf _site
bundle exec jekyll serve --config _config.yml,_config_development.yml --incremental
```

## Production

Testing production build:
```
rm -rf _site
JEKYLL_ENV=production jekyll build
```
