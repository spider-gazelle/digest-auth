require "uri"
require "mutex"
require "openssl"
require "process"
require "digest/md5"

# maintain basic backwards compatibility
{% if compare_versions(Crystal::VERSION, "0.36.0") < 0 %}
  class URI
    def request_target
      full_path
    end
  end
{% end %}

# An implementation of RFC 2617 Digest Access Authentication.
class DigestAuth
  class Error < Exception; end

  @nonce_count = -1_i64
  @mutex = Mutex.new

  # Creates a digest auth header
  # IIS servers handle the "qop" parameter of digest authentication
  # differently so you may need to set `iis` to true for such servers.
  # ameba:disable Metrics/CyclomaticComplexity
  def auth_header(uri : URI, www_authenticate : String, method : String, iis : Bool = false)
    nonce_count = next_nonce
    user = URI.decode(uri.user || "")
    password = URI.decode(uri.password || "")
    method = method.strip.upcase

    # Grab the key pairs
    www_authenticate =~ /^(\w+) (.*)/
    challenge = $2

    # Put them in a hash
    params = {} of String => String
    challenge.gsub(/(\w+)="(.*?)"/) { params[$1] = $2 }

    # Work out the algorithm to use
    alg_string = if challenge.includes?("algorithm=")
                   challenge =~ /algorithm="?(.*?)"?([, ]|$)/
                   $1
                 else
                   "MD5"
                 end

    alg_string =~ /(.*?)(-sess)?$/
    alg_check = $1
    algorithm = case alg_check
                when "MD5"
                  OpenSSL::Digest.new("MD5")
                when "SHA1"
                  OpenSSL::Digest.new("SHA1")
                when "SHA2"
                  OpenSSL::Digest.new("SHA2")
                when "SHA256"
                  OpenSSL::Digest.new("SHA256")
                when "SHA384"
                  OpenSSL::Digest.new("SHA384")
                when "SHA512"
                  OpenSSL::Digest.new("SHA512")
                when "RMD160"
                  OpenSSL::Digest.new("RMD160")
                else
                  raise DigestAuth::Error.new("unknown algorithm: #{alg_check}")
                end
    sess = $2?

    realm = params["realm"]
    nonce = params["nonce"]
    qop = params["qop"]?
    cnonce = qop || sess ? make_cnonce : ""

    if sess
      algorithm.update("#{user}:#{realm}:#{password}".to_slice)
      a1 = {
        algorithm.final.hexstring,
        nonce,
        cnonce.to_s,
      }.join(':')
      algorithm.reset
    else
      a1 = "#{user}:#{realm}:#{password}"
    end

    ha1 = algorithm.update(a1.to_slice).final.hexstring
    algorithm.reset
    ha2 = algorithm.update("#{method}:#{uri.request_target}".to_slice).final.hexstring
    algorithm.reset

    nonce_count_string = ("%08x" % nonce_count)
    request_digest = [ha1, nonce]
    request_digest.push(nonce_count_string, cnonce, qop) if qop
    request_digest << ha2
    request_digest = request_digest.join ':'

    header = [
      %(Digest username="#{user}"),
      %(realm="#{realm}"),
      "algorithm=#{alg_string}",
    ]

    if qop
      header << (iis ? %(qop="#{qop}") : "qop=#{qop}")
    end

    header << %(uri="#{uri.request_target}")
    header << %(nonce="#{nonce}")

    if qop
      header << "nc=#{nonce_count_string}"
      header << %(cnonce="#{cnonce}")
    end

    header << %(response="#{algorithm.update(request_digest.to_slice).final.hexstring}")

    if opaque = params["opaque"]?
      header << %(opaque="#{opaque}")
    end

    header.join(", ")
  end

  protected def next_nonce
    @mutex.synchronize { @nonce_count += 1_i64 }
  end

  protected def make_cnonce
    digest = Digest::MD5.digest do |ctx|
      ctx.update Time.utc.to_unix.to_s
      ctx.update ":"
      ctx.update Process.pid.to_s
      ctx.update ":"
      ctx.update Random::Secure.rand(UInt32::MAX).to_s
    end
    digest.hexstring
  end
end
