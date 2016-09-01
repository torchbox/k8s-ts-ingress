#! /usr/bin/env perl
# vim:set sw=2 ts=2 et:

use strict;
use warnings;

use LWP::UserAgent;
use JSON qw/decode_json/;
use Data::Dumper;
use Digest::MD5 qw/md5_hex/;
use MIME::Base64 qw/decode_base64/;

my $ua = LWP::UserAgent->new();

my $apiroot;
my $testmode = 0;
my $ssldir = '/usr/local/etc/trafficserver/ssl';
my $must_reload = 0;

if (@ARGV > 0 and $ARGV[0] eq '--test') {
  print STDERR "test mode\n";
  $apiroot = $ARGV[1];
  $ua->ssl_opts(
    SSL_cert_file => $ARGV[2],
    SSL_key_file  => $ARGV[3],
    SSL_ca_file   => $ARGV[4]);
  $testmode = 1;
  $ssldir = './certs';
  open REMAP, ">./remap.config";
} else {
  my $cacertfile = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt";
  my $tokenfile = "/var/run/secrets/kubernetes.io/serviceaccount/token";

  open TOKEN, "<$tokenfile" or die "$tokenfile: $!";
  my $token = <TOKEN>;
  chomp($token);
  close TOKEN;

  $apiroot = "https://$ENV{KUBERNETES_SERVICE_HOST}:$ENV{KUBERNETES_PORT_443_TCP_PORT}";
  $ua->default_header("Authorization" => "Bearer $token");
  $ua->ssl_opts('SSL_ca_file' => $cacertfile);
  open REMAP, ">/usr/local/etc/trafficserver/remap.config";
}

if (!-d $ssldir) {
  mkdir($ssldir);
}

my $remap_extra = "\@plugin=remap_purge.so \@pparam=--state-file=/var/lib/trafficserver/genid_<hostname>.kch \@pparam=--secret=purge-domain-cache \@pparam=--header=x-cache-action \@pparam=--allow-get \@plugin=cachekey.so \@pparam=--sort-params=true \@pparam=--include-headers=X-Forwarded-Proto \@pparam=--static-prefix=<protocol> \@pparam=--capture-prefix=(.*):(.*) \@pparam=--exclude-match-params=^utm_.*";

my $nsresp = $ua->get($apiroot . "/api/v1/namespaces");
my $ret = decode_json $nsresp->content;

my @remaps;
my @tls;

sub get_service_ip {
  my $nsname = shift;
  my $service = shift;
  my $svcresp = $ua->get($apiroot . "/api/v1/namespaces/${nsname}/services/${service}");
  my $svcret = decode_json $svcresp->content;

  return $svcret->{'spec'}->{'clusterIP'};
}

foreach my $namespace (@{$ret->{'items'}}) {
  my $nsname = $namespace->{'metadata'}->{'name'};
  my $ingresp = $ua->get($apiroot . "/apis/extensions/v1beta1/namespaces/${nsname}/ingresses/");
  my $ingret = decode_json $ingresp->content;

  foreach my $ingress (@{$ingret->{'items'}}) {
    my $spec = $ingress->{'spec'};
    my $rules = $spec->{'rules'};

    if (exists($spec->{'tls'})) {
      foreach my $spectls (@{$spec->{'tls'}}) {
        push @tls, {
          namespace => $nsname,
          secret    => $spectls->{'secretName'},
        };
      }
    }

    foreach my $rule (@{$rules}) {
      my $host = undef;
      if (exists $rule->{'host'}) {
        $host = $rule->{'host'};
      }

      if (exists $rule->{'http'} and exists $rule->{'http'}{'paths'}) {
        my @paths = @{$rule->{'http'}{'paths'}};
        foreach my $path (sort { length($a->{'path'}) <=> length($b->{'path'}) }  @paths) {
          my $prefix = $path->{'path'};
          my $backend = $path->{'backend'};
          my $backhost = $backend->{'serviceName'};
          my $backport = $backend->{'servicePort'};
          my $backip = get_service_ip($nsname, $backhost);
          my $service = "$backip:$backport";

          push @remaps, { host => $host, prefix => $prefix, service => $service };
        }
      }
    }
  }
}

foreach my $remap (sort { length($b->{'prefix'}) <=> length($a->{'prefix'}) } @remaps) {
  my $host = $remap->{'host'};
  my $service = $remap->{'service'};
  my $prefix = $remap->{'prefix'};

	if (defined $host) {
		my $this_extra = $remap_extra;
		$this_extra =~ s/<hostname>/$host/g;
		$this_extra =~ s/<protocol>/http/g;
		print REMAP "map http://$host$prefix http://$service$prefix $this_extra\n";

		$this_extra = $remap_extra;
		$this_extra =~ s/<hostname>/$host/g;
		$this_extra =~ s/<protocol>/https/g;
		print REMAP "map https://$host$prefix http://$service$prefix $this_extra\n";

		$this_extra = $remap_extra;
		$this_extra =~ s/<hostname>/$host/g;
		$this_extra =~ s/<protocol>/ws/g;
		print REMAP "map ws://$host$prefix ws://$service$prefix $this_extra\n";

		$this_extra = $remap_extra;
		$this_extra =~ s/<hostname>/$host/g;
		$this_extra =~ s/<protocol>/wss/g;
		print REMAP "regex_map wss://$host$prefix ws://$service$prefix $this_extra\n";
	} else {
		my $this_extra = $remap_extra;
		$this_extra =~ s/<hostname>/__ANY__/g;
		$this_extra =~ s/<protocol>/http/g;
		print REMAP "regex_map http://[A-Za-z0-9-]+$prefix http://$service$prefix $this_extra\n";

		$this_extra = $remap_extra;
		$this_extra =~ s/<hostname>/__ANY__/g;
		$this_extra =~ s/<protocol>/https/g;
		print REMAP "regex_map http://[A-Za-z0-9-]+$prefix https://$service$prefix $this_extra\n";

		$this_extra = $remap_extra;
		$this_extra =~ s/<hostname>/__ANY__/g;
		$this_extra =~ s/<protocol>/ws/g;
		print REMAP "regex_map ws://[A-Za-z0-9-]+$prefix ws://$service$prefix $this_extra\n";

		$this_extra = $remap_extra;
		$this_extra =~ s/<hostname>/__ANY__/g;
		$this_extra =~ s/<protocol>/wss/g;
		print REMAP "regex_map wss://[A-Za-z0-9-]+$prefix ws://$service$prefix $this_extra\n";
	}
}

my $multicert_new = "";

foreach my $tls (@tls) {
  my $nsname = $tls->{'namespace'};
  my $secret = $tls->{'secret'};

  my $secresp = $ua->get($apiroot . "/api/v1/namespaces/${nsname}/secrets/$secret");
  my $secrt = decode_json $secresp->content;

  my $certfile = $ssldir."/$nsname-$secret.crt";

  $multicert_new .= "dest_ip=* ssl_cert_name=$certfile\n";

  my $new_key = decode_base64 $secrt->{'data'}->{'tls.key'};
  my $new_cert = decode_base64 $secrt->{'data'}->{'tls.crt'};
  my $combined = $new_key . "\n" . $new_cert . "\n";
  my $new_hash = md5_hex($combined);

  if (-f $certfile) {
    my $current;
    {
      local $/ = undef;
      open CUR, "<$certfile";
      binmode CUR;
      $current = <CUR>;
      close CUR;
    }

    my $cur_hash = md5_hex($current);

    if ($new_hash eq $cur_hash) {
      next;
    }
  }

  open CERT, ">$certfile";
  print CERT $combined;
  close CERT;
  $must_reload = 1;
}

my $multicert_current;
{
  local $/ = undef;
  open CUR, "</usr/local/etc/trafficserver/ssl_multicert.config";
  binmode CUR;
  $multicert_current = <CUR>;
  close CUR;
}

if (md5_hex($multicert_current) ne md5_hex($multicert_new)) {
  open MC, ">/usr/local/etc/trafficserver/ssl_multicert.config";
  binmode MC;
  print MC $multicert_new;
  $must_reload = 1;
}

if ($must_reload) {
  print "remap.pl: reloading TS configuration.";
  system("/usr/local/bin/traffic_ctl", "config", "reload");
}
