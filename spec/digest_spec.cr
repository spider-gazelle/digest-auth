require "./spec_helper"

# mock out make_cnonce so it's predictable
class DigestAuth
  def make_cnonce
    # run the old method to catch any errors
    previous_def
    "9ea5ff3bd34554a4165bbdc1df91dcff"
  end
end

describe DigestAuth do
  uri = URI.parse "http://www.example.com/"
  uri.user = "user"
  uri.password = "password"

  header = ""
  expected = [] of String
  auth = DigestAuth.new

  Spec.before_each do
    header = {
      %(Digest qop="auth"),
      %(realm="www.example.com"),
      %(nonce="4107baa081a592a6021660200000cd6c5686ff5f579324402b374d83e2c9"),
    }.join(", ")

    expected = [
      %(Digest username="user"),
      %(realm="www.example.com"),
      %(algorithm=MD5),
      %(qop=auth),
      %(uri="/"),
      %(nonce="4107baa081a592a6021660200000cd6c5686ff5f579324402b374d83e2c9"),
      %(nc=00000000),
      %(cnonce="9ea5ff3bd34554a4165bbdc1df91dcff"),
      %(response="67be92a5e7b38d08679957db04f5da04"),
    ]

    auth = DigestAuth.new
  end

  it "should generate an auth header" do
    expected.join(", ").should eq(auth.auth_header(uri, header, "get"))

    # Next nonce
    expected[6] = "nc=00000001"
    expected[8] = %(response="1f5f0cd1588690c1303737f081c0b9bb")

    auth.auth_header(uri, header, "get").should eq(expected.join(", "))
  end

  it "should work with an IIS auth header" do
    expected[3] = %(qop="auth")
    auth.auth_header(uri, header, "get", iis: true).should eq(expected.join(", "))
  end

  it "should work no qop" do
    header = header.sub %( qop="auth",), ""

    expected[8] = %(response="32f6ca1631ccf7c42a8075deff44e470")
    expected.delete "qop=auth"
    expected.delete %(cnonce="9ea5ff3bd34554a4165bbdc1df91dcff")
    expected.delete "nc=00000000"

    auth.auth_header(uri, header, "get").should eq(expected.join(", "))
  end

  it "should work with an opaque header" do
    expected << %(opaque="5ccc069c403ebaf9f0171e9517f40e41")
    header += %(opaque="5ccc069c403ebaf9f0171e9517f40e41")

    auth.auth_header(uri, header, "get").should eq(expected.join(", "))
  end

  it "should work with a POST request" do
    expected[8] = %(response="d82219e1e5430b136bbae1670fa51d48")

    auth.auth_header(uri, header, "post").should eq(expected.join(", "))
  end

  it "should work with a algorithm sess" do
    header += ", algorithm=MD5-sess"
    expected[2] = "algorithm=MD5-sess"
    expected[8] = %(response="c22c5bd9112a86ca78ddc1ae772daeeb")
    auth.auth_header(uri, header, "get").should eq(expected.join(", "))
  end

  it "should work with a SHA1 algorithm" do
    expected[2] = "algorithm=SHA1"
    expected[8] = %(response="2cb62fc18f7b0ebdc34543f896bb77686b4115e4")

    header = header + ", algorithm=SHA1"
    auth.auth_header(uri, header, "get").should eq(expected.join(", "))
  end

  it "should raise an error on an unknown algorithm" do
    header += ", algorithm=bogus"

    expect_raises(DigestAuth::Error) do
      auth.auth_header(uri, header, "get").should eq(expected.join(", "))
    end
  end

  it "should work with a quoted algorithm" do
    header += %(, algorithm="MD5")
    auth.auth_header(uri, header, "get").should eq(expected.join(", "))
  end
end
