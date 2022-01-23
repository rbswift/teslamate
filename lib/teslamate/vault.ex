defmodule TeslaMate.Vault do
  use Cloak.Vault,
    otp_app: :teslamate

  defmodule Encrypted.Binary do
    use Cloak.Ecto.Binary, vault: TeslaMate.Vault
  end

  require Logger

  # In AES.GCM, it is important to specify 12-byte IV length for
  # interoperability with other encryption software. See this GitHub
  # issue for more details: https://github.com/danielberkompas/cloak/issues/93
  @iv_length 12

  @impl GenServer
  def init(config) do
    config = Keyword.put(config, :ciphers, default: default_chipher(encryption_key()))
    {:ok, config}
  end

  def default_chipher(key) do
    {Cloak.Ciphers.AES.GCM, tag: "AES.GCM.V1", key: key, iv_length: @iv_length}
  end

  defp encryption_key do
    key =
      case System.get_env("ENCRYPTION_KEY") do
        key when is_binary(key) and byte_size(key) > 0 ->
          key

        _ ->
          random_key =
            :crypto.strong_rand_bytes(32)
            |> Base.encode64()
            |> binary_part(0, 16)

          Logger.warn("""
          --------------------------------------------------------------------
          No ENCRYPTION_KEY was found to encrypt and decrypt API tokens. Therefore, a
          random key was generated automatically for you:


                                      #{random_key}


          Create an environment variable named "ENCRYPTION_KEY" with the value of this
          key and pass it to this application from now on.

          Otherwise, a new login with your API tokens will required after every restart.
          ------------------------------------------------------------------------------
          """)

          random_key
      end

    :crypto.hash(:sha256, key)
  end
end
