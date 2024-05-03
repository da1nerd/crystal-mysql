require "socket"
require "openssl"
require "../ext/openssl"

class MySql::Connection < DB::Connection
  def initialize(context : DB::ConnectionContext)
    super(context)
    @mutex = Mutex.new
    @socket = uninitialized TCPSocket | OpenSSL::SSL::Socket::Client

    begin
      host = context.uri.hostname || raise "no host provided"
      port = context.uri.port || 3306
      username = context.uri.user
      password = context.uri.password

      path = context.uri.path
      if path && path.size > 1
        initial_catalog = path[1..-1]
      else
        initial_catalog = nil
      end

      io = TCPSocket.new(host, port)
      io.sync = false

      # begin
      #   io = OpenSSL::SSL::Socket::Client.new(io, context: default_ssl_context, sync_close: true, hostname: host)
      # rescue exc
      #   io.close
      #   raise exc
      # end

      @socket = io
      handshake = read_packet(Protocol::HandshakeV10)

      # TODO: only request SSL if the server supports it and the user requested it.
      write_packet(1) do |packet|
        Protocol::SSLRequest.new(username, password, initial_catalog, handshake.auth_plugin_data).write(packet)
      end
      # TODO: fix negotiating ssl
      negotiate_ssl(host)

      write_packet(1) do |packet|
        Protocol::HandshakeResponse41.new(username, password, initial_catalog, handshake.auth_plugin_data).write(packet)
      end

      read_ok_or_err do |packet, status|
        raise "packet #{status} not implemented"
      end
    rescue e : IO::Error
      puts e.message
      puts e.backtrace
      raise DB::ConnectionRefused.new
    end
  end

  private def negotiate_ssl(host)
    begin
      @socket = OpenSSL::SSL::Socket::Client.new(@socket, context: default_ssl_context, sync_close: true)
    rescue e
      @socket.close
      raise e
    end
    return

    # outline
    # send ClientHello specifying the highest TLS protocol version supported, a random number, a list of cipher suites, and suggested compression methods.
    # server responds with ServerHello containing protocal version, random number, cipher suite selections.
    # server sends Certificate message, depending..
    # server sends ServerKeyExchange message, depending...
    # server sends ServerHelloDone message
    # client sends ClientKeyExchange message, may contain a PreMasterSecret, public key, or nothing depending on the selected cipher.
    #

    write_i32 8 # handshake type (encrypted_extension)
    write_i32 80877103
    @socket.flush

    if process_ssl_message
      ctx = OpenSSL::SSL::Context::Client.new
      ctx.verify_mode = OpenSSL::SSL::VerifyMode::NONE # currently emulating sslmode 'require' not verify_ca or verify_full
      # if sslcert = @conninfo.sslcert
      #   ctx.certificate_chain = sslcert
      # end
      # if sslkey = @conninfo.sslkey
      #   ctx.private_key = sslkey
      # end
      # if sslrootcert = @conninfo.sslrootcert
      #   ctx.ca_certificates = sslrootcert
      # end
      @socket = OpenSSL::SSL::Socket::Client.new(@socket, context: ctx, sync_close: true)
    end

    if !@socket.is_a?(OpenSSL::SSL::Socket::Client)
      close
      raise "sslmode=require and server did not establish SSL"
    end
  end

  private def process_ssl_message : Bool
    bytes = Bytes.new(1024)
    read_count = @socket.read(bytes)

    puts "Response:\n #{bytes.hexdump}"

    # Make sure there are no surprise, unencrypted data in the socket, potentially from an attacker
    unless read_count == 1
      raise "Unexpected data after SSL response:\n#{bytes[0, read_count].hexdump}"
    end

    case c = bytes[0]
    when 'S' then true
    when 'N' then false
    else
      raise "Unexpected SSL response from server: #{c.inspect}"
    end
  end

  def close
    synchronize do
      return if @socket.closed?
      send_terminate_message
      @socket.close
    end
  end

  def synchronize
    @mutex.synchronize { yield }
  end

  private def write_i32(i : Int32)
    @socket.write_bytes i, IO::ByteFormat::NetworkEndian
  end

  private def write_i32(i)
    write_i32 i.to_i32
  end

  # :nodoc:
  private def default_ssl_context
    context = OpenSSL::SSL::Context::Client.new
    context.verify_mode = OpenSSL::SSL::VerifyMode::NONE
    context.ciphers = "EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH"
    context.add_options(OpenSSL::SSL::Options::NO_SSL_V2 | OpenSSL::SSL::Options::NO_SSL_V3)
    context
  end

  def do_close
    super

    begin
      write_packet do |packet|
        Protocol::Quit.new.write(packet)
      end
      @socket.close
    rescue
    end
  end

  # :nodoc:
  def read_ok_or_err
    read_packet do |packet|
      raise_if_err_packet(packet) do |status|
        yield packet, status
      end
    end
  end

  private def write_chr(chr : Char)
    @socket.write_byte chr.ord.to_u8
  end

  # :nodoc:
  def read_packet
    puts "read packet"
    packet = build_read_packet
    begin
      yield packet
    ensure
      packet.discard
    end
  end

  def send_terminate_message
    write_chr 'X'
    write_i32 4
  end

  # :nodoc:
  def read_packet(protocol_packet_type)
    puts "read protocal packet"
    read_packet do |packet|
      return protocol_packet_type.read(packet)
    end
    raise "unable to read packet"
  end

  # :nodoc:
  def build_read_packet
    ReadPacket.new(@socket, self)
  end

  # :nodoc:
  def write_packet(seq = 0)
    content = IO::Memory.new
    yield WritePacket.new(content, self)
    bytesize = content.bytesize

    packet = IO::Memory.new
    3.times do
      packet.write_byte (bytesize & 0xff_u8).to_u8
      bytesize >>= 8
    end
    packet.write_byte seq.to_u8

    packet << content

    @socket << packet
    @socket.flush
  end

  # :nodoc:
  def handle_err_packet(packet)
    8.times { packet.read_byte! }
    raise packet.read_string
  end

  # :nodoc:
  def raise_if_err_packet(packet)
    raise_if_err_packet(packet) do |status|
      raise "unexpected packet #{status}"
    end
  end

  # :nodoc:
  def raise_if_err_packet(packet)
    status = packet.read_byte!
    if status == 255
      handle_err_packet packet
    end

    yield status if status != 0

    status
  end

  # :nodoc:
  def read_column_definitions(target, column_count)
    # Parse column definitions
    # http://dev.mysql.com/doc/internals/en/com-query-response.html#packet-Protocol::ColumnDefinition
    column_count.times do
      self.read_packet do |packet|
        catalog = packet.read_lenenc_string
        schema = packet.read_lenenc_string
        table = packet.read_lenenc_string
        org_table = packet.read_lenenc_string
        name = packet.read_lenenc_string
        org_name = packet.read_lenenc_string
        next_length = packet.read_lenenc_int # length of fixed-length fields, always 0x0c
        raise "Unexpected next_length value: #{next_length}." unless next_length == 0x0c
        character_set = packet.read_fixed_int(2).to_u16!
        column_length = packet.read_fixed_int(4).to_u32!
        column_type = packet.read_fixed_int(1).to_u8!
        flags = packet.read_fixed_int(2).to_u16!
        decimal = packet.read_fixed_int(1).to_u8!
        filler = packet.read_fixed_int(2).to_u16! # filler [00] [00]
        raise "Unexpected filler value #{filler}" unless filler == 0x0000

        target << ColumnSpec.new(catalog, schema, table, org_table, name, org_name, character_set, column_length, column_type, flags, decimal)
      end
    end

    if column_count > 0
      self.read_packet do |eof_packet|
        eof_packet.read_byte # TODO assert EOF Packet
      end
    end
  end

  def build_prepared_statement(query) : MySql::Statement
    MySql::Statement.new(self, query)
  end

  def build_unprepared_statement(query) : MySql::UnpreparedStatement
    MySql::UnpreparedStatement.new(self, query)
  end
end
