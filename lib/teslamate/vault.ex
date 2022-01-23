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
    case get_encryption_key() do
      {:ok, _key} -> true
      :error -> false
    end
  end

  @impl GenServer
  def init(config) do
    encryption_key =
      case get_encryption_key() do
        {:ok, key} ->
          key

        :error ->
          key_length = 48 + :rand.uniform(16)
          random_key = generate_random_key(key_length)

          Logger.warning("""
          \n------------------------------------------------------------------------------
          No ENCRYPTION_KEY was found to encrypt and decrypt API tokens. Therefore, a
          random key was generated automatically for you:


          #{pad(random_key, 80)}


          Create an environment variable named "ENCRYPTION_KEY" with the value of this
          key and pass it to this application from now on.

          OTHERWISE, A LOGIN WITH YOUR API TOKENS WILL BE REQUIRED AFTER EVERY RESTART.
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

  defp pad(string, width) do
    case String.length(string) do
      len when len < width ->
        n = div(width - len, 2)

        string
        |> String.pad_leading(n + len)
        |> String.pad_trailing(width)

      _ ->
        string
    end
  end

  defp get_encryption_key do
    case System.get_env("ENCRYPTION_KEY") do
      key when is_binary(key) and byte_size(key) > 0 -> {:ok, key}
      _ -> :error
    end
  end

  defp generate_random_key(length) when length > 31 do
    :crypto.strong_rand_bytes(length) |> Base.encode64(padding: false) |> binary_part(0, length)
  end
end
