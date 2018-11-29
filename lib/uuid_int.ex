defmodule UUIDInt do
  @moduledoc """
  UUIDInt allows you to encode an integer into a UUID and decode it back from
  the generated UUID.
  """

  @uuid_bit_size 16 * 8

  @doc """
  Encode an unsigned integer into a UUID

  ## Examples

      iex> UUIDInt.encode(3)
      {:ok, "86666835-06aa-cd90-0bbd-5a74ac4e0308"}
      iex> UUIDInt.encode(4322343)
      {:ok, "07bfef02-a615-2803-edf7-8bc841f42718"}
      iex> UUIDInt.encode(1329227995784915872903807060280344575)
      {:ok, "ffffffff-ffff-ffff-ffff-ffffffffff78"}

  """
  ## prefix (md5(uint)) + uint (var) + bit size of uint (2 chars)

  def encode(uint) do
    bitsize = bitsize(uint)
    input_bytes = << uint::size(bitsize) >>

    prefix = prefix(input_bytes, bitsize + 8)
    UUIDInt.UUIDHex.encode(prefix <> input_bytes <> << bitsize::size(8) >> )
  end

  @doc """
  Decode an uuid_int into an unsigned integer

  ## Examples

      iex> UUIDInt.decode("86666835-06aa-cd90-0bbd-5a74ac4e0308")
      {:ok, 3}
      iex> UUIDInt.decode("07bfef02-a615-2803-edf7-8bc841f42718")
      {:ok, 4322343}
      iex> UUIDInt.decode("ffffffff-ffff-ffff-ffff-ffffffffff78")
      {:ok, 1329227995784915872903807060280344575}

  """
  def decode(uuid) do
    {:ok, << prefix_with_uint::binary-size(15), size::size(8) >>} = UUIDInt.UUIDHex.decode(uuid)

    prefix_byte_size = @uuid_bit_size - size - 8

    << _prefix::size(prefix_byte_size), uint::size(size) >> = prefix_with_uint

    {:ok, uint}
  end



  # ####################
  # private
  # ####################


  defp prefix(input_bytes, suffix_size) do
    prefix_byte_size = (@uuid_bit_size - suffix_size) |> Kernel./(8) |> round
    hash = :crypto.hash(:md5, input_bytes)
    << prefix::binary-size(prefix_byte_size), _rest::binary >>  = hash
    prefix
  end


  defp bitsize(1), do: 8
  defp bitsize(n) do
    n              # e.g. 34
    |> :math.log2  # => 5.08 (number of bits required to store this)
    |> Kernel./(8) # => 0.63 (number of bytes required )
    |> :math.ceil  # => 1.0  (number of whole nibbles)
    |> round       # => 1    (convert to int)
    |> Kernel.*(8) # => 8    (number of bits in whole bytes)
  end


  defmodule UUIDHex do

  @typedoc """
  A hex-encoded UUID string.
  """
  @type t :: <<_::288>>

  @typedoc """
  A raw binary representation of a UUID.
  """
  @type raw :: <<_::128>>

  @doc """
  Converts a binary UUID into a string.
  """
  @spec encode(raw | any) :: {:ok, t} | :error
  def encode(<< a1::4, a2::4, a3::4, a4::4,
                 a5::4, a6::4, a7::4, a8::4,
                 b1::4, b2::4, b3::4, b4::4,
                 c1::4, c2::4, c3::4, c4::4,
                 d1::4, d2::4, d3::4, d4::4,
                 e1::4, e2::4, e3::4, e4::4,
                 e5::4, e6::4, e7::4, e8::4,
                 e9::4, e10::4, e11::4, e12::4 >>) do
    << e(a1), e(a2), e(a3), e(a4), e(a5), e(a6), e(a7), e(a8), ?-,
       e(b1), e(b2), e(b3), e(b4), ?-,
       e(c1), e(c2), e(c3), e(c4), ?-,
       e(d1), e(d2), e(d3), e(d4), ?-,
       e(e1), e(e2), e(e3), e(e4), e(e5), e(e6), e(e7), e(e8), e(e9), e(e10), e(e11), e(e12) >>
  catch
    :error -> :error
  else
    encoded -> {:ok, encoded}
  end
  def encode(_), do: :error


  @doc """
  Converts a string representing a UUID into a binary.
  """
  @spec decode(t | any) :: {:ok, raw} | :error
  def decode(<< a1, a2, a3, a4, a5, a6, a7, a8, ?-,
              b1, b2, b3, b4, ?-,
              c1, c2, c3, c4, ?-,
              d1, d2, d3, d4, ?-,
              e1, e2, e3, e4, e5, e6, e7, e8, e9, e10, e11, e12 >>) do
    try do
      << d(a1)::4, d(a2)::4, d(a3)::4, d(a4)::4,
         d(a5)::4, d(a6)::4, d(a7)::4, d(a8)::4,
         d(b1)::4, d(b2)::4, d(b3)::4, d(b4)::4,
         d(c1)::4, d(c2)::4, d(c3)::4, d(c4)::4,
         d(d1)::4, d(d2)::4, d(d3)::4, d(d4)::4,
         d(e1)::4, d(e2)::4, d(e3)::4, d(e4)::4,
         d(e5)::4, d(e6)::4, d(e7)::4, d(e8)::4,
         d(e9)::4, d(e10)::4, d(e11)::4, d(e12)::4 >>
    catch
      :error -> :error
    else
      binary ->
        {:ok, binary}
    end
  end
  def decode(_), do: :error

  @compile {:inline, d: 1}

  defp d(?0), do: 0
  defp d(?1), do: 1
  defp d(?2), do: 2
  defp d(?3), do: 3
  defp d(?4), do: 4
  defp d(?5), do: 5
  defp d(?6), do: 6
  defp d(?7), do: 7
  defp d(?8), do: 8
  defp d(?9), do: 9
  defp d(?A), do: 10
  defp d(?B), do: 11
  defp d(?C), do: 12
  defp d(?D), do: 13
  defp d(?E), do: 14
  defp d(?F), do: 15
  defp d(?a), do: 10
  defp d(?b), do: 11
  defp d(?c), do: 12
  defp d(?d), do: 13
  defp d(?e), do: 14
  defp d(?f), do: 15
  defp d(_),  do: throw(:error)

  @compile {:inline, e: 1}

  defp e(0),  do: ?0
  defp e(1),  do: ?1
  defp e(2),  do: ?2
  defp e(3),  do: ?3
  defp e(4),  do: ?4
  defp e(5),  do: ?5
  defp e(6),  do: ?6
  defp e(7),  do: ?7
  defp e(8),  do: ?8
  defp e(9),  do: ?9
  defp e(10), do: ?a
  defp e(11), do: ?b
  defp e(12), do: ?c
  defp e(13), do: ?d
  defp e(14), do: ?e
  defp e(15), do: ?f
  end
end
