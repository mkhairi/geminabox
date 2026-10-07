FROM ruby:4.0

RUN mkdir -p /usr/src/app
WORKDIR /usr/src/app

COPY . /usr/src/app
# config.ru defaults to /data. Point it at the volume path the README uses.
ENV GEMINABOX_DATA=/usr/src/app/data
# Install exactly what Gemfile.lock pins; fail if it is missing or stale.
# Development and test gems stay out of the image.
# data/ must exist before the chown so a named volume mounted there
# inherits appuser ownership instead of root's.
RUN bundle config set --local frozen true \
 && bundle config set --local without 'development test' \
 && bundle install \
 && mkdir -p /usr/src/app/data \
 && useradd -m -u 1000 appuser \
 && chown -R appuser:appuser /usr/src/app
USER appuser

EXPOSE 9292

ENTRYPOINT ["bundle", "exec", "rackup", "--host", "0.0.0.0"]
