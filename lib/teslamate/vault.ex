defmodule TeslaMate.Vault do
  use Cloak.Vault,
    otp_app: :teslamate

  defmodule Encrypted.Binary do
    use Cloak.Ecto.Binary, vault: TeslaMate.Vault
  end

  require Logger

  # With AES.GCM, 12-byte IV length is necessary for interoperability reasons.
  # See https://github.com/danielberkompas/cloak/issues/93
  @iv_length 12

  def default_chipher(key) do
    {Cloak.Ciphers.AES.GCM, tag: "AES.GCM.V1", key: key, iv_length: @iv_length}
  end

  def encryption_key_provided? do
    case encryption_key() do
      {:ok, _key} -> true
      :error -> false
    end
  end

  @impl GenServer
  def init(config) do
    encryption_key =
      case encryption_key() do
        {:ok, key} ->
          key

        :error ->
          random_key = generate_random_key()

          Logger.warn("""
          --------------------------------------------------------------------
          No ENCRYPTION_KEY was found to encrypt and decrypt API tokens. Therefore, a
          random key was generated automatically for you:


                                      #{random_key}


          Create an environment variable named "ENCRYPTION_KEY" with the value of this
          key and pass it to this application from now on.

          OTHERWISE, A NEW LOGIN WITH YOUR API TOKENS WILL REQUIRED AFTER EVERY RESTART.
          ------------------------------------------------------------------------------
          """)

          random_key
      end

    config =
      Keyword.put(config, :ciphers,
        default: default_chipher(:crypto.hash(:sha256, encryption_key))
      )

    {:ok, config}
  end

  defp encryption_key do
    case System.get_env("ENCRYPTION_KEY") do
      key when is_binary(key) and byte_size(key) > 0 -> {:ok, key}
      _ -> :error
    end
  end

  defp generate_random_key do
    :crypto.strong_rand_bytes(32) |> Base.encode64() |> binary_part(0, 16)
  end
end
