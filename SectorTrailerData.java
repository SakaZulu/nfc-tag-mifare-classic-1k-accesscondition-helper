
import java.math.BigInteger;
import java.nio.ByteBuffer;



public class SectorTrailerData {

	private byte[] KeyA;
	private byte[] AccessControl;
	private byte[] KeyB;
	
	public SectorTrailerData() {
		KeyA = new byte[]{(byte) 0xFF,(byte) 0xFF,(byte) 0xFF,(byte) 0xFF,(byte) 0xFF,(byte) 0xFF};
		KeyB = new byte[]{(byte) 0xFF,(byte) 0xFF,(byte) 0xFF,(byte) 0xFF,(byte) 0xFF,(byte) 0xFF};
		AccessControl = new byte[]{ (byte) 0xFF,(byte) 0x07,(byte) 0x80,(byte) 0x63};
	}
	
	public byte[] getdata(){
		byte[] data = new byte[16]; 
		System.arraycopy(KeyA, 0, data, 0, 6);
		System.arraycopy(AccessControl, 0, data, 6, 4);
		System.arraycopy(KeyB, 0, data, 10, 6);
		return data;
	}
	
	public void setdata(byte[] newKeyA,byte[] newKeyB, byte[] newAcessControl){
		KeyA = newKeyA;
		KeyB = newKeyB;
		AccessControl = newAcessControl;
	}
	
	public void setdata(byte[] data){
		System.arraycopy(data, 0, KeyA, 0, 6);
		System.arraycopy(data, 6, AccessControl, 0, 4);
		System.arraycopy(data, 10, KeyB, 0, 6);
	}
	
	public byte[] GenerateAccessControl(String firstBlockSetting, String secondBlockSetting, String thirdBlockSetting, String SectorTrailerSetting) {
		
		return GenerateAccessControl(firstBlockSetting, secondBlockSetting, thirdBlockSetting, SectorTrailerSetting, AccessControl[3]);
	}
	

	public byte[] GenerateAccessControl(String firstBlockSetting, String secondBlockSetting, String thirdBlockSetting, String SectorTrailerSetting, byte userData) {
		String[] binBytes = {""+Invert(SectorTrailerSetting.charAt(1))+Invert(thirdBlockSetting.charAt(1))+Invert(secondBlockSetting.charAt(1))+Invert(firstBlockSetting.charAt(1))+Invert(SectorTrailerSetting.charAt(0))+Invert(thirdBlockSetting.charAt(0))+Invert(secondBlockSetting.charAt(0))+Invert(firstBlockSetting.charAt(0)),
							 ""+SectorTrailerSetting.charAt(0)+thirdBlockSetting.charAt(0)+secondBlockSetting.charAt(0)+firstBlockSetting.charAt(0)+Invert(SectorTrailerSetting.charAt(2))+Invert(thirdBlockSetting.charAt(2))+Invert(secondBlockSetting.charAt(2))+Invert(firstBlockSetting.charAt(2)),
							 ""+SectorTrailerSetting.charAt(2)+thirdBlockSetting.charAt(2)+secondBlockSetting.charAt(2)+firstBlockSetting.charAt(2)+SectorTrailerSetting.charAt(1)+thirdBlockSetting.charAt(1)+secondBlockSetting.charAt(1)+firstBlockSetting.charAt(1)};
		ByteBuffer bytes = ByteBuffer.allocate(4).putInt(Integer.parseInt(binBytes[0]+binBytes[1]+binBytes[2], 2));
		System.arraycopy(bytes.array(),1,AccessControl,0,3);
		AccessControl[3] = userData;
		return AccessControl;
	}
	
	char Invert(char bin){
		if(bin == '1')
			return (char)'0';
		else
			return (char)'1';
	}
	
	public SectorTrailerData SetSectorTrailerValues(byte[] newKeyA,byte[] newAcessControl,byte[] newKeyB) {
		setdata(newKeyA,newKeyB,newAcessControl);
		return this;
	}

	public void SetKeyA(String newKeyA) {
		if(newKeyA.length() == 6)
		{
			for(int i=0;i<6;i++)
			{
				KeyA[i] = (byte) ((Character.digit(newKeyA.charAt(i*2), 16) << 4)
	                  + Character.digit(newKeyA.charAt((i*2)+1), 16));
			}
		}
	}
	
	public void SetKeyB(String newKeyB) {
		if(newKeyB.length() == 6){
			for(int i=0;i<6;i++)
			{
				KeyB[i] = (byte) ((Character.digit(newKeyB.charAt(i*2), 16) << 4)
	                  + Character.digit(newKeyB.charAt((i*2)+1), 16));
			}
		}
	}
	
	public void SetKeyA(byte[] newKeyA) {
		KeyA = newKeyA;
	}
	
	public void SetKeyB(byte[] newKeyB) {
		KeyB = newKeyB;
	}

	public byte[] getKeyA() {
		return KeyA;
	}
	
	public byte[] getKeyB() {
		return KeyB;
	}

	public String GetReadKey(int block) {
		String accessCondition= getAccessConditionByBlock(block);
		if(block < 3)
		{
			if(accessCondition.equalsIgnoreCase("111"))
			{
				return "never";
			}else if(accessCondition.equalsIgnoreCase("011") || accessCondition.equalsIgnoreCase("011"))
			{
				return "B";
			}else 
				return "A|B";
		}else
			return accessCondition;
	}
	
	public String GetWriteKey(int block) {
		String accessCondition= getAccessConditionByBlock(block);
		if(block < 3)
		{
			if(accessCondition.equalsIgnoreCase("000"))
			{
				return "A|B";
			}else if(accessCondition.equalsIgnoreCase("010") || accessCondition.equalsIgnoreCase("100") || accessCondition.equalsIgnoreCase("101") || accessCondition.equalsIgnoreCase("111"))
			{
				return "never";
			}else 
				return "A";
		}else
			return accessCondition;
	}
	
	public String getAccessConditionByBlock(int block) {
		String[] bin= new String[3];
		for(int i=0;i<3;i++)
		{
			String zeros= new String();
			byte[] val = {AccessControl[i]};
			int temp = Integer.parseInt(bin2hex(val), 16);
		    bin[i] = Integer.toBinaryString(temp);
			if(bin[i].length() < 8)
				for(int j =0;j<8-bin[i].length();j++)
						zeros += "0";
				bin[i] = zeros+bin[i];
		}
		return new String(""+bin[1].charAt(3-block)+bin[2].charAt(7-block)+bin[2].charAt(3-block));
	}
	
	static String bin2hex(byte[] data) {
	    return String.format("%0" + (data.length * 2) + "X", new BigInteger(1,data));
	}
	
}
