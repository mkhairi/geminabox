# Two stages: build compiles native gems (bcrypt) with a compiler, and the
# runtime image gets only Ruby, the installed gems, and the app.

FROM ruby:4.0-slim AS build

RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/app
# Install exactly what Gemfile.lock pins. Fail if it is missing or stale.
# Development and test gems stay out of the image.
ENV BUNDLE_FROZEN=true \
    BUNDLE_WITHOUT="development test"

# Gems first, so code changes reuse the cached gem layer. The gemspec
# reads lib/geminabox/version.rb.
COPY Gemfile Gemfile.lock geminabox.gemspec ./
COPY lib/geminabox/version.rb lib/geminabox/version.rb
RUN bundle install --jobs 4 \
 && rm -rf /usr/local/bundle/cache \
 && find /usr/local/bundle -type d -name cache -prune -exec rm -rf {} + \
 && find /usr/local/bundle/gems -name "*.o" -delete

COPY . .


FROM ruby:4.0-slim

WORKDIR /usr/src/app
# config.ru defaults to /data. Point it at the volume path the README uses.
# production keeps rackup from adding middleware that shows stack traces.
ENV BUNDLE_FROZEN=true \
    BUNDLE_WITHOUT="development test" \
    GEMINABOX_DATA=/usr/src/app/data \
    RACK_ENV=production

# The app code stays owned by root, so the app cannot modify itself.
# Only data/ belongs to appuser. It must exist before a named volume is
# mounted there, so the volume inherits appuser ownership.
RUN useradd -m -u 1000 appuser \
 && mkdir -p /usr/src/app/data \
 && chown appuser:appuser /usr/src/app/data

COPY --from=build /usr/local/bundle /usr/local/bundle
COPY --from=build /usr/src/app /usr/src/app

USER appuser
EXPOSE 9292

# /login is open, so it answers without credentials.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["ruby", "-rnet/http", "-e", "exit(Net::HTTP.get_response(URI('http://127.0.0.1:9292/login')).is_a?(Net::HTTPSuccess) ? 0 : 1)"]

ENTRYPOINT ["bundle", "exec", "rackup", "--host", "0.0.0.0", "--port", "9292"]
