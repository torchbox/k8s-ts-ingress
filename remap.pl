#! /usr/bin/env perl
# vim:set sw=2 ts=2 et:

use strict;
use warnings;

use LWP::UserAgent;
use JSON qw/decode_json/;
use Data::Dumper;

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
          my $service = "http://".$backhost.'.'.$ENV{'CLUSTER_DNS_SUFFIX'}.':'.$backport.'/';

          if (defined $host) {
            print "map http://$host$prefix $service\n";
          } else {
            print "regex_map http://[A-Za-z0-9-]+$prefix $service\n";
          }
        }
      }
    }
  }
}
