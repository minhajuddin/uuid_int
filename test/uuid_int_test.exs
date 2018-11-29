defmodule UUIDIntTest do
  use ExUnit.Case
  doctest UUIDInt

  use ExUnitProperties

  describe "#encode" do
    test "encodes int to uuid" do
      assert UUIDInt.encode(3) == {:ok, "86666835-06aa-cd90-0bbd-5a74ac4e0301"}
    end
  end

  describe "#decode" do
    test "decodes uuid to int" do
      assert UUIDInt.decode("86666835-06AA-cd90-0bbd-5a74ac4e0301") == {:ok, 3}
    end
  end

  property "encode -> decode returns the same int" do
    check all uint <- StreamData.integer |> StreamData.filter(& &1 > 0) do
      {:ok, uuid} = UUIDInt.encode(uint)
      {:ok, dec_uint} = UUIDInt.decode(uuid)

      assert uint == dec_uint
    end
  end
end
