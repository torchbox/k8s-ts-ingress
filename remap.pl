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
my $remap_file = '/usr/local/etc/trafficserver/remap.config';
my $multicert_file = '/usr/local/etc/trafficserver/remap.config';

if (@ARGV > 0 and $ARGV[0] eq '--test') {
  print STDERR "test mode\n";
  $apiroot = $ARGV[1] || 'https://master.kube.itl.rslon.torchbox.net:8443';
  $ua->ssl_opts(
    SSL_cert_file => $ARGV[2] || '/home/ft/.kube/admin@kube.itl.rslon.torchbox.net.crt',
    SSL_key_file  => $ARGV[3] || '/home/ft/.kube/admin@kube.itl.rslon.torchbox.net.key',
    SSL_ca_file   => $ARGV[4] || '/etc/ssl/certs/tbx-ca.pem',
  );
  $testmode = 1;
  $ssldir = './certs';
  $remap_file = './remap.config';
  $multicert_file = './ssl_multicert.config';
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
}

if (!-d $ssldir) {
  mkdir($ssldir);
}

my $remap_extra = "\@plugin=remap_purge.so \@pparam=--state-file=/var/lib/trafficserver/genid_<hostname>.kch \@pparam=--secret=purge-domain-cache \@pparam=--header=x-cache-action \@pparam=--allow-get \@plugin=cachekey.so \@pparam=--sort-params=true \@pparam=--include-headers=X-Forwarded-Proto \@pparam=--static-prefix=<protocol> \@pparam=--capture-prefix=(.*):(.*) \@pparam=--exclude-match-params=^utm_.*";

my $nsresp = $ua->get($apiroot . "/api/v1/namespaces");
my $ret = decode_json $nsresp->content;

my @remaps;
my @tls;

sub check_file_changed {
  my $file = shift;
  my $new = shift;

  if (!-f $file) {
    return 1;
  }

  local $/ = undef;
  open CUR, "<$file";
  binmode CUR;
  my $current = <CUR>;
  close CUR;

  if (md5_hex($current) ne md5_hex($new)) {
    return 1;
  } else {
    return 0;
  }
}

sub get_service_ip {
  my $nsname = shift;
  my $service = shift;
  my $svcresp = $ua->get($apiroot . "/api/v1/namespaces/${nsname}/services/${service}");
  my $svcret = decode_json $svcresp->content;

  return $svcret->{'spec'}->{'clusterIP'};
}

sub handle_deis_service {
  my $deisdomain = shift;
  my $svc = shift;
  my $svcname = $svc->{'metadata'}->{'name'};
  my $svcns = $svc->{'metadata'}->{'namespace'};

  print "handling deis service $svcns/$svcname\n";
  my @domains = split(",", $svc->{'metadata'}->{'annotations'}->{'router.deis.io/domains'});
  return unless @domains;

  foreach my $port (@{$svc->{'spec'}->{'ports'}}) {
    my $backport = $port->{'port'};

    foreach my $domain (@domains) {
      print "domain: $domain/$backport\n";
      my $backip = get_service_ip($svcns, $svcname);
      
      my $service = "$backip:$backport";
      $domain =~ s/$/.$deisdomain/ if $domain !~ /\./;
      push @remaps, { host => $domain, prefix => '/', service => $service };
    }
  }
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

  my $svcsresp = $ua->get($apiroot . "/api/v1/namespaces/${nsname}/services/");
  if ($svcsresp->is_success) {
    my $svcsret = decode_json $svcsresp->content;

    my $deisresp = $ua->get($apiroot . "/api/v1/namespaces/${nsname}/replicationcontrollers/deis-router");
    if ($deisresp->is_success) {
      my $deisret = decode_json $deisresp->content;
      my $deisdomain = $deisret->{'metadata'}->{'annotations'}->{'router.deis.io/nginx.platformDomain'};

      foreach my $service (@{$svcsret->{'items'}}) {
        if (defined($service->{'metadata'}->{'labels'}->{'router.deis.io/routable'}) and
            $service->{'metadata'}->{'labels'}->{'router.deis.io/routable'} eq 'true')
        {
          handle_deis_service($deisdomain, $service);
        }
      }
    }
  }
}

my $remap_content = "";

foreach my $remap (sort { length($b->{'prefix'} || '/') <=> length($a->{'prefix'} || '/') } @remaps) {
  my $host = $remap->{'host'};
  my $service = $remap->{'service'};
  my $prefix = $remap->{'prefix'} || '/';

	if (defined $host) {
		my $this_extra = $remap_extra;
		$this_extra =~ s/<hostname>/$host/g;
		$this_extra =~ s/<protocol>/http/g;
		$remap_content .= "map http://$host$prefix http://$service$prefix $this_extra\n";

		$this_extra = $remap_extra;
		$this_extra =~ s/<hostname>/$host/g;
		$this_extra =~ s/<protocol>/https/g;
		$remap_content .= "map https://$host$prefix http://$service$prefix $this_extra\n";

		$this_extra = $remap_extra;
		$this_extra =~ s/<hostname>/$host/g;
		$this_extra =~ s/<protocol>/ws/g;
		$remap_content .= "map ws://$host$prefix ws://$service$prefix $this_extra\n";

		$this_extra = $remap_extra;
		$this_extra =~ s/<hostname>/$host/g;
		$this_extra =~ s/<protocol>/wss/g;
		$remap_content .= "regex_map wss://$host$prefix ws://$service$prefix $this_extra\n";
	} else {
		my $this_extra = $remap_extra;
		$this_extra =~ s/<hostname>/__ANY__/g;
		$this_extra =~ s/<protocol>/http/g;
		$remap_content .= "regex_map http://[A-Za-z0-9-]+$prefix http://$service$prefix $this_extra\n";

		$this_extra = $remap_extra;
		$this_extra =~ s/<hostname>/__ANY__/g;
		$this_extra =~ s/<protocol>/https/g;
		$remap_content .= "regex_map http://[A-Za-z0-9-]+$prefix https://$service$prefix $this_extra\n";

		$this_extra = $remap_extra;
		$this_extra =~ s/<hostname>/__ANY__/g;
		$this_extra =~ s/<protocol>/ws/g;
		$remap_content .= "regex_map ws://[A-Za-z0-9-]+$prefix ws://$service$prefix $this_extra\n";

		$this_extra = $remap_extra;
		$this_extra =~ s/<hostname>/__ANY__/g;
		$this_extra =~ s/<protocol>/wss/g;
		$remap_content .= "regex_map wss://[A-Za-z0-9-]+$prefix ws://$service$prefix $this_extra\n";
	}
}

my $multicert_new = "";

foreach my $tls (@tls) {
  my $nsname = $tls->{'namespace'};
  my $secret = $tls->{'secret'};

  my $secresp = $ua->get($apiroot . "/api/v1/namespaces/${nsname}/secrets/$secret");
  next unless $secresp->is_success;
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

if (check_file_changed($multicert_file, $multicert_new)) {
  print "remap.pl: ssl_multicert.config has changed\n";
  open MC, ">$multicert_file";
  binmode MC;
  print MC $multicert_new;
  close MC;
  $must_reload = 1;
}

if (check_file_changed($remap_file, $remap_content)) {
  print "remap.pl: remap.config has changed\n";
  open RM, ">$remap_file";
  binmode RM;
  print RM $remap_content;
  close RM;
  $must_reload = 1;
}

if ($must_reload) {
  print "remap.pl: reloading TS configuration.\n";
  system("/usr/local/bin/traffic_ctl", "config", "reload");
}
