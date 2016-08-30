#! /usr/bin/env perl
# vim:set sw=2 ts=2 et:

use strict;
use warnings;

use LWP::UserAgent;
use JSON qw/decode_json/;
use Data::Dumper;

my $remap_extra = "\@plugin=remap_purge.so \@pparam=--state-file=/var/lib/trafficserver/genid_<hostname>.kch \@pparam=--secret=__domain_purge__";

my $certfile = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt";
my $tokenfile = "/var/run/secrets/kubernetes.io/serviceaccount/token";

open TOKEN, "<$tokenfile" or die "$tokenfile: $!";
my $token = <TOKEN>;
chomp($token);
close TOKEN;

my $apiroot = "https://$ENV{KUBERNETES_SERVICE_HOST}:$ENV{KUBERNETES_PORT_443_TCP_PORT}";

my $ua = LWP::UserAgent->new();
$ua->default_header("Authorization" => "Bearer $token");
$ua->ssl_opts('SSL_ca_file' => $certfile);

my $nsresp = $ua->get($apiroot . "/api/v1/namespaces");
my $ret = decode_json $nsresp->content;

foreach my $namespace (@{$ret->{'items'}}) {
  my $nsname = $namespace->{'metadata'}->{'name'};
  my $ingresp = $ua->get($apiroot . "/apis/extensions/v1beta1/namespaces/${nsname}/ingresses/");
  my $ingret = decode_json $ingresp->content;

  foreach my $ingress (@{$ingret->{'items'}}) {
    my $rules = $ingress->{'spec'}{'rules'};

    foreach my $rule (@{$rules}) {
      my $host = undef;
      if (exists $rule->{'host'}) {
        $host = $rule->{'host'};
      }

      if (exists $rule->{'http'} and exists $rule->{'http'}{'paths'}) {
        foreach my $path (@{$rule->{'http'}{'paths'}}) {
          my $prefix = $path->{'path'};
          my $backend = $path->{'backend'};
          my $backhost = $backend->{'serviceName'} . '.' . $nsname;
          my $backport = $backend->{'servicePort'};
          my $service = $backhost.'.'.$ENV{'CLUSTER_DNS_SUFFIX'}.':'.$backpor;

          my $this_extra = $remap_extra;

          if (defined $host) {
            $this_extra =~ s/<hostname>/$host/g;
            print "map http://$host$prefix http://$service$prefix $this_extra\n";
            print "map ws://$host$prefix ws://$service$prefix $this_extra\n";
          } else {
            $this_extra =~ s/<hostname>/__ANY__/g;
            print "regex_map http://[A-Za-z0-9-]+$prefix http://$service$prefix $this_extra\n";
            print "regex_map ws://[A-Za-z0-9-]+$prefix ws://$service$prefix $this_extra\n";
          }
        }
      }
    }
  }
}
