AWS Fargate doesn't currently allow overriding DNS configuration. In some rare cases
this can lead to hitting the linklocal allowance. This program was written to allow
caching of DNS queries for short periods of time in order to avoid hitting this
limit.

It might have other uses too if you're lazy and don't want to fix your app...
Alternatives include for instance configuring and running NSCD inside the container,
but it will cause a local network request for every resolver call.
